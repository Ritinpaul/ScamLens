import asyncio
import json
import sys
import time
from pathlib import Path

# Ensure unbuffered output and utf-8 encoding when redirected to log files
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")

from backend.app.core.normalizer import normalize_text
from backend.app.services.deterministic_verifier import DeterministicVerifier
from backend.app.services.ai_provider import OllamaProvider
from backend.app.services.decision_engine import DecisionEngine
from backend.app.services.image_extractor import ImageTextExtractor
from backend.app.models.verifier_schema import SignalSeverity

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CURATED_PATH = ROOT_DIR / "data" / "evaluation" / "curated_cases.json"
RESULTS_PATH = ROOT_DIR / "data" / "evaluation" / "evaluation_results.json"
SCREENSHOT_PATH = ROOT_DIR / "data" / "examples" / "test_screenshot.png"

async def run_evaluation():
    print("=" * 70)
    print("SCAMLENS STAGE 4: SECURITY EVALUATION & PIPELINE BENCHMARK")
    print("=" * 70)

    with open(CURATED_PATH, "r", encoding="utf-8") as f:
        cases = json.load(f)

    verifier = DeterministicVerifier()
    ai_provider = OllamaProvider()
    engine = DecisionEngine()
    image_extractor = ImageTextExtractor()

    scam_cases = [c for c in cases if c["expected_class"] == "scam"]
    legit_cases = [c for c in cases if c["expected_class"] == "legitimate"]

    print(f"Loaded {len(cases)} curated cases ({len(scam_cases)} scams, {len(legit_cases)} legitimate).")

    # =========================================================================
    # PHASE 1: DETERMINISTIC VERIFIER EVALUATION
    # =========================================================================
    print("\n[Phase 1] Evaluating Deterministic Verifier...")
    det_results = []
    scams_with_signal = 0
    legit_with_critical = 0
    legit_with_any_signal = 0
    fp_signal_categories = []

    for c in cases:
        normalized_text = normalize_text(c["text"])
        v_out = verifier.verify(normalized_text)
        has_signal = len(v_out.signals) > 0
        has_critical = any(s.severity == SignalSeverity.CRITICAL for s in v_out.signals)

        if c["expected_class"] == "scam" and has_signal:
            scams_with_signal += 1

        if c["expected_class"] == "legitimate":
            if has_critical:
                legit_with_critical += 1
            if has_signal:
                legit_with_any_signal += 1
                for s in v_out.signals:
                    fp_signal_categories.append({"id": c["id"], "category": s.category, "snippet": s.snippet, "severity": s.severity.value})

        det_results.append({
            "id": c["id"],
            "expected_class": c["expected_class"],
            "risk_level": v_out.deterministic_risk_level,
            "signal_count": len(v_out.signals),
            "signals": [s.model_dump(mode='json') for s in v_out.signals],
            "urls": [u.model_dump(mode='json') for u in v_out.urls],
        })

    print(f"  Deterministic signal coverage on scams: {scams_with_signal}/{len(scam_cases)} ({scams_with_signal/len(scam_cases)*100:.1f}%)")
    print(f"  False critical signals on legitimate messages: {legit_with_critical}/{len(legit_cases)} ({legit_with_critical/len(legit_cases)*100:.1f}%)")
    print(f"  False non-critical signals on legitimate messages: {legit_with_any_signal}/{len(legit_cases)}")

    # =========================================================================
    # PHASE 2: REAL LOCAL LLAMA 3 SEMANTIC EVALUATION
    # =========================================================================
    print("\n[Phase 2] Evaluating Real Local Llama 3 Semantic Model (no mocks)...")
    ai_results = []
    model_scam_correct = 0
    model_legit_fp = 0
    model_exact_correct = 0
    model_latencies = []

    for idx, c in enumerate(cases):
        normalized_text = normalize_text(c["text"])
        t0 = time.perf_counter()
        ai_out = await ai_provider.analyze_text(normalized_text)
        lat = time.perf_counter() - t0
        model_latencies.append(lat)

        is_scam_predicted = ai_out.verdict.value in ("scam", "suspicious")
        if c["expected_class"] == "scam" and is_scam_predicted:
            model_scam_correct += 1
        if c["expected_class"] == "legitimate" and is_scam_predicted:
            model_legit_fp += 1

        exact_match = (
            (c["expected_class"] == "scam" and ai_out.verdict.value == "scam") or
            (c["expected_class"] == "legitimate" and ai_out.verdict.value == "likely_legitimate")
        )
        if exact_match:
            model_exact_correct += 1

        print(f"  [{idx+1:02d}/{len(cases):02d}] {c['id']:<26} | Exp: {c['expected_class']:<10} | Model: {ai_out.verdict.value:<16} | {lat:.2f}s")

        ai_dict = ai_out.model_dump(mode='json')
        ai_dict["id"] = c["id"]
        ai_dict["model_verdict"] = ai_out.verdict.value
        ai_dict["latency_seconds"] = round(lat, 2)
        ai_dict["expected_class"] = c["expected_class"]
        ai_results.append(ai_dict)

    model_recall = model_scam_correct / len(scam_cases) if scam_cases else 0.0
    model_fp_rate = model_legit_fp / len(legit_cases) if legit_cases else 0.0
    model_acc = model_exact_correct / len(cases)

    print(f"  Model Scam Recall (scam/suspicious): {model_scam_correct}/{len(scam_cases)} ({model_recall*100:.1f}%)")
    print(f"  Model Legitimate False Positive Rate: {model_legit_fp}/{len(legit_cases)} ({model_fp_rate*100:.1f}%)")
    print(f"  Model Exact Accuracy: {model_exact_correct}/{len(cases)} ({model_acc*100:.1f}%)")
    print(f"  Model Latency Avg: {sum(model_latencies)/len(model_latencies):.2f}s (Min: {min(model_latencies):.2f}s, Max: {max(model_latencies):.2f}s)")

    # =========================================================================
    # PHASE 3: COMBINED PIPELINE EVALUATION (Normalizer + AI + Verifier + Decision Engine)
    # =========================================================================
    print("\n[Phase 3] Evaluating Combined Pipeline Decision Engine...")
    combined_results = []
    combined_scam_correct = 0
    combined_legit_fp = 0
    combined_exact_correct = 0
    disagreement_count = 0
    insufficient_count = 0

    for idx, c in enumerate(cases):
        normalized_text = normalize_text(c["text"])
        from backend.app.models.ai_schema import AiAnalysisOutput
        ai_dict = dict(ai_results[idx])
        ai_dict.pop("id", None)
        ai_dict.pop("model_verdict", None)
        ai_dict.pop("latency_seconds", None)
        ai_dict.pop("expected_class", None)
        ai_out = AiAnalysisOutput.model_validate(ai_dict)
        v_out = verifier.verify(normalized_text)

        final_resp = engine.synthesize(
            ai_output=ai_out,
            verifier_output=v_out,
            raw_snippet=normalized_text,
            normalized_length=len(normalized_text),
            input_type="pasted_text"
        )

        is_scam_final = final_resp.verdict.value in ("scam", "suspicious")
        if c["expected_class"] == "scam" and is_scam_final:
            combined_scam_correct += 1
        if c["expected_class"] == "legitimate" and is_scam_final:
            combined_legit_fp += 1

        exact_match = (
            (c["expected_class"] == "scam" and final_resp.verdict.value == "scam") or
            (c["expected_class"] == "legitimate" and final_resp.verdict.value == "likely_legitimate")
        )
        if exact_match:
            combined_exact_correct += 1

        if final_resp.verdict.value == "insufficient_evidence":
            insufficient_count += 1

        if any("SAFETY OVERRIDE" in r for r in final_resp.decision_rationale):
            disagreement_count += 1

        combined_results.append({
            "id": c["id"],
            "expected_class": c["expected_class"],
            "final_verdict": final_resp.verdict.value,
            "confidence": final_resp.confidence.value,
            "decision_rationale": final_resp.decision_rationale,
            "plain_english_summary": final_resp.plain_english_summary,
            "recommended_action": final_resp.recommended_action,
        })

    combined_recall = combined_scam_correct / len(scam_cases)
    combined_fp_rate = combined_legit_fp / len(legit_cases)
    combined_acc = combined_exact_correct / len(cases)

    print(f"  Combined Scam Recall: {combined_scam_correct}/{len(scam_cases)} ({combined_recall*100:.1f}%)")
    print(f"  Combined False Positive Rate: {combined_legit_fp}/{len(legit_cases)} ({combined_fp_rate*100:.1f}%)")
    print(f"  Combined Exact Accuracy: {combined_exact_correct}/{len(cases)} ({combined_acc*100:.1f}%)")
    print(f"  Model/Verifier Disagreements (Overrides): {disagreement_count}")
    print(f"  Insufficient Evidence Cases: {insufficient_count}")

    # =========================================================================
    # PHASE 4: REMOVE-AI DEMONSTRATION (CASE A & CASE B)
    # =========================================================================
    print("\n[Phase 4] Remove-AI Proof Comparison...")
    case_a = next(c for c in cases if c["id"] == "scam_bank_kyc_01")
    case_b = next(c for c in cases if c["id"] == "scam_pure_social_eng_08")

    def evaluate_remove_ai(case_obj):
        text = normalize_text(case_obj["text"])
        ver = verifier.verify(text)
        # Deterministic-only verdict
        has_crit = any(s.severity == SignalSeverity.CRITICAL for s in ver.signals)
        has_hi = any(s.severity == SignalSeverity.HIGH for s in ver.signals)
        det_only_verdict = "scam" if has_crit else ("suspicious" if has_hi else "likely_legitimate")

        # AI-only verdict
        ai_res = next(a for a in ai_results if a["id"] == case_obj["id"])
        ai_only_verdict = ai_res["model_verdict"]

        # Combined verdict
        comb_res = next(cr for cr in combined_results if cr["id"] == case_obj["id"])
        combined_verdict = comb_res["final_verdict"]

        return {
            "id": case_obj["id"],
            "category": case_obj["category"],
            "deterministic_only": {
                "verdict": det_only_verdict,
                "signals": [s.pattern_matched for s in ver.signals],
                "risk_level": ver.deterministic_risk_level,
            },
            "ai_only": {
                "verdict": ai_only_verdict,
                "tactics": [t["type"] for t in ai_res["tactics"]],
                "summary": ai_res["summary"],
            },
            "combined": {
                "verdict": combined_verdict,
                "confidence": comb_res["confidence"],
                "rationale": comb_res["decision_rationale"],
            }
        }

    case_a_eval = evaluate_remove_ai(case_a)
    case_b_eval = evaluate_remove_ai(case_b)

    print("\n--- CASE A: Technical Indicators Exist (Bank KYC Phishing) ---")
    print(f"  Deterministic-Only: {case_a_eval['deterministic_only']['verdict'].upper()} (Signals: {case_a_eval['deterministic_only']['signals']})")
    print(f"  AI-Only:            {case_a_eval['ai_only']['verdict'].upper()} (Tactics: {case_a_eval['ai_only']['tactics']})")
    print(f"  Combined Result:    {case_a_eval['combined']['verdict'].upper()} (Rationale: {case_a_eval['combined']['rationale'][0]})")

    print("\n--- CASE B: Pure Social Engineering without URLs or Payment Keywords (Family Emergency Pretext) ---")
    print(f"  Deterministic-Only: {case_b_eval['deterministic_only']['verdict'].upper()} (Signals: {case_b_eval['deterministic_only']['signals']})")
    print(f"  AI-Only:            {case_b_eval['ai_only']['verdict'].upper()} (Tactics: {case_b_eval['ai_only']['tactics']})")
    print(f"  Combined Result:    {case_b_eval['combined']['verdict'].upper()} (Rationale: {case_b_eval['combined']['rationale'][0]})")

    # =========================================================================
    # PHASE 5: LATENCY BENCHMARKS (Text, OCR, Full Screenshot Pipeline)
    # =========================================================================
    print("\n[Phase 5] Measuring Latency Profiles (Min, Max, Avg)...")
    with open(SCREENSHOT_PATH, "rb") as f:
        img_bytes = f.read()

    # 1. Text Analysis Latency (3 samples)
    text_latencies = []
    sample_text = "Urgent: Your account is suspended. Verify immediately at http://example.com"
    for i in range(3):
        t0 = time.perf_counter()
        await ai_provider.analyze_text(sample_text)
        text_latencies.append(time.perf_counter() - t0)

    # 2. Screenshot OCR Latency (3 samples)
    ocr_latencies = []
    for i in range(3):
        t0 = time.perf_counter()
        image_extractor.extract_text_from_bytes(img_bytes)
        ocr_latencies.append(time.perf_counter() - t0)

    # 3. Screenshot Complete Pipeline (2 samples)
    full_screenshot_latencies = []
    for i in range(2):
        t0 = time.perf_counter()
        raw_text, meta = image_extractor.extract_text_from_bytes(img_bytes)
        norm_text = normalize_text(raw_text)
        ai_out = await ai_provider.analyze_text(norm_text)
        ver_out = verifier.verify(norm_text)
        engine.synthesize(
            ai_output=ai_out,
            verifier_output=ver_out,
            raw_snippet=raw_text,
            normalized_length=len(norm_text),
            input_type="screenshot_ocr",
            extracted_ocr_text=raw_text,
            image_metadata=meta
        )
        full_screenshot_latencies.append(time.perf_counter() - t0)

    latency_report = {
        "text_analysis_seconds": {
            "samples": [round(x, 2) for x in text_latencies],
            "min": round(min(text_latencies), 2),
            "max": round(max(text_latencies), 2),
            "avg": round(sum(text_latencies) / len(text_latencies), 2),
        },
        "screenshot_ocr_seconds": {
            "samples": [round(x, 2) for x in ocr_latencies],
            "min": round(min(ocr_latencies), 2),
            "max": round(max(ocr_latencies), 2),
            "avg": round(sum(ocr_latencies) / len(ocr_latencies), 2),
        },
        "screenshot_complete_pipeline_seconds": {
            "samples": [round(x, 2) for x in full_screenshot_latencies],
            "min": round(min(full_screenshot_latencies), 2),
            "max": round(max(full_screenshot_latencies), 2),
            "avg": round(sum(full_screenshot_latencies) / len(full_screenshot_latencies), 2),
        }
    }

    print(f"  Text Analysis Latency: Avg {latency_report['text_analysis_seconds']['avg']}s (Min {latency_report['text_analysis_seconds']['min']}s, Max {latency_report['text_analysis_seconds']['max']}s)")
    print(f"  Screenshot OCR Latency: Avg {latency_report['screenshot_ocr_seconds']['avg']}s (Min {latency_report['screenshot_ocr_seconds']['min']}s, Max {latency_report['screenshot_ocr_seconds']['max']}s)")
    print(f"  Screenshot Complete Pipeline: Avg {latency_report['screenshot_complete_pipeline_seconds']['avg']}s (Min {latency_report['screenshot_complete_pipeline_seconds']['min']}s, Max {latency_report['screenshot_complete_pipeline_seconds']['max']}s)")

    # =========================================================================
    # PHASE 6: OCR BEFORE VS AFTER ANALYSIS
    # =========================================================================
    print("\n[Phase 6] OCR Before vs After Inspection...")
    ocr_raw_text, ocr_meta = image_extractor.extract_text_from_bytes(img_bytes)
    verified_ocr = verifier.verify(ocr_raw_text)

    ocr_comparison = {
        "ground_truth_url": "http://sbi-kyc.xyz/verify",
        "before_hardening_extracted_text": "Update your KYC immediately http lsbi-kycxyz verify",
        "after_hardening_extracted_text": ocr_raw_text,
        "after_hardening_metadata": ocr_meta,
        "after_hardening_detected_urls": [u.model_dump(mode='json') for u in verified_ocr.urls],
        "after_hardening_signals": [s.model_dump(mode='json') for s in verified_ocr.signals],
        "uncertainty_flagged": verified_ocr.has_uncertain_urls,
    }

    print("  OCR Raw Text Extracted:")
    for line in ocr_raw_text.splitlines():
        print("    ", line)
    print("  Detected URLs with Certainty:")
    for u in verified_ocr.urls:
        print(f"    - Raw: '{u.raw_url}' | Certainty: {u.certainty.value} | Candidate: '{u.reconstructed_candidate}'")

    # =========================================================================
    # SAVE STRUCTURED EVALUATION RESULTS
    # =========================================================================
    final_evaluation_payload = {
        "dataset_summary": {
            "total_cases": len(cases),
            "scam_cases": len(scam_cases),
            "legitimate_cases": len(legit_cases),
        },
        "deterministic_results": {
            "scam_signal_coverage": f"{scams_with_signal}/{len(scam_cases)}",
            "scam_coverage_percentage": round(scams_with_signal / len(scam_cases) * 100, 1),
            "false_critical_signals": f"{legit_with_critical}/{len(legit_cases)}",
            "false_signals_list": fp_signal_categories,
        },
        "model_results": {
            "model_name": "llama3:latest",
            "scam_recall": round(model_recall, 3),
            "legitimate_false_positive_rate": round(model_fp_rate, 3),
            "exact_classification_accuracy": round(model_acc, 3),
            "latency": latency_report["text_analysis_seconds"],
        },
        "combined_results": {
            "scam_recall": round(combined_recall, 3),
            "legitimate_false_positive_rate": round(combined_fp_rate, 3),
            "exact_classification_accuracy": round(combined_acc, 3),
            "disagreements_resolved": disagreement_count,
            "insufficient_evidence_cases": insufficient_count,
        },
        "remove_ai_cases": {
            "case_a": case_a_eval,
            "case_b": case_b_eval,
        },
        "latency_benchmarks": latency_report,
        "ocr_before_after": ocr_comparison,
        "per_case_details": {
            "deterministic": det_results,
            "model": ai_results,
            "combined": combined_results,
        }
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(final_evaluation_payload, f, indent=2)

    print(f"\nSaved structured evaluation report to {RESULTS_PATH}")
    print("=" * 70)

if __name__ == "__main__":
    asyncio.run(run_evaluation())
