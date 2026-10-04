import json
from pathlib import Path
import pytest
from backend.app.services.deterministic_verifier import DeterministicVerifier
from backend.app.services.decision_engine import DecisionEngine
from backend.app.models.ai_schema import AiAnalysisOutput, TacticItem
from backend.app.models.verifier_schema import VerifierOutput, DetectedSignal, SignalSeverity

CURATED_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "evaluation" / "curated_cases.json"

@pytest.fixture
def evaluation_cases():
    assert CURATED_PATH.exists(), f"Evaluation dataset not found at {CURATED_PATH}"
    with open(CURATED_PATH, "r", encoding="utf-8") as f:
        cases = json.load(f)
    return cases

def test_evaluation_dataset_loading_and_counts(evaluation_cases):
    assert len(evaluation_cases) >= 16
    scams = [c for c in evaluation_cases if c["expected_class"] == "scam"]
    legit = [c for c in evaluation_cases if c["expected_class"] == "legitimate"]
    assert len(scams) >= 8
    assert len(legit) >= 8

def test_evaluation_cases_schema_conformance(evaluation_cases):
    required_keys = {
        "id", "category", "expected_class", "text",
        "expected_semantic_tactics", "expected_deterministic_signals", "notes"
    }
    valid_classes = {"scam", "legitimate", "ambiguous"}

    for case in evaluation_cases:
        assert required_keys.issubset(case.keys()), f"Missing keys in case {case.get('id')}"
        assert case["expected_class"] in valid_classes
        assert isinstance(case["text"], str) and len(case["text"]) > 10
        assert isinstance(case["expected_semantic_tactics"], list)
        assert isinstance(case["expected_deterministic_signals"], list)
        assert isinstance(case["notes"], str)

def test_legitimate_messages_trigger_no_critical_deterministic_signals(evaluation_cases):
    verifier = DeterministicVerifier()
    legit_cases = [c for c in evaluation_cases if c["expected_class"] == "legitimate"]
    
    for case in legit_cases:
        res = verifier.verify(case["text"])
        # Legitimate messages should never trigger critical signals (such as direct OTP solicitation or raw IP links)
        critical_signals = [s for s in res.signals if s.severity == SignalSeverity.CRITICAL]
        assert len(critical_signals) == 0, f"False critical signal in legitimate case {case['id']}: {critical_signals}"

def test_decision_engine_disagreement_resolution():
    engine = DecisionEngine()
    
    # Scenario: AI model hallucinated safe/legitimate, but deterministic verifier caught critical OTP request
    mock_ai_safe = AiAnalysisOutput(
        source="model",
        model_name="llama3:latest",
        verdict="likely_legitimate",
        summary="Message claims to be security support.",
        recommended_action="Verify independently before taking action.",
        confidence_label="model_unvalidated",
    )
    mock_verifier_critical = VerifierOutput(
        source="deterministic",
        has_otp_request=True,
        deterministic_risk_level="critical",
        signals=[
            DetectedSignal(
                category="otp_harvesting",
                pattern_matched="Direct request to disclose OTP/verification code",
                snippet="share the OTP",
                severity=SignalSeverity.CRITICAL,
            )
        ]
    )
    
    # Critical deterministic rule MUST override AI misclassification
    result = engine.synthesize(
        ai_output=mock_ai_safe,
        verifier_output=mock_verifier_critical,
        raw_snippet="WhatsApp Support: Share the OTP received immediately.",
        normalized_length=50,
    )
    
    assert result.verdict == "scam"
    assert result.confidence == "high"
    assert any("CRITICAL RULE TRIGGERED" in r for r in result.decision_rationale)
    assert any("SAFETY OVERRIDE" in r for r in result.decision_rationale)

def test_remove_ai_demonstration_cases(evaluation_cases):
    verifier = DeterministicVerifier()
    engine = DecisionEngine()
    
    # Case A: Technical indicator exists (Bank KYC phishing with credential request & domain mismatch)
    case_a = next(c for c in evaluation_cases if c["id"] == "scam_bank_kyc_01")
    ver_a = verifier.verify(case_a["text"])
    
    # Verifier alone catches critical/high signals
    assert ver_a.deterministic_risk_level in ("critical", "high")
    assert ver_a.has_credential_request is True
    
    # Case B: Pure social engineering without URLs or payment keywords (Family emergency pretext)
    case_b = next(c for c in evaluation_cases if c["id"] == "scam_pure_social_eng_08")
    ver_b = verifier.verify(case_b["text"])
    
    # Deterministic verifier ALONE sees NO signals (cannot understand family emergency pretext)
    assert len(ver_b.signals) == 0
    assert ver_b.deterministic_risk_level == "none"
    
    # But when AI semantic analysis evaluates the impersonation tactic:
    ai_b = AiAnalysisOutput(
        source="model",
        model_name="llama3:latest",
        verdict="scam",
        summary="Impersonation of family member under pretext of broken phone to solicit passwords.",
        tactics=[
            TacticItem(type="identity_impersonation", evidence="Hi Mom, my phone fell into water"),
            TacticItem(type="emotional_pretext", evidence="send me family password for insurance binder"),
        ],
        recommended_action="Do not disclose passwords over unverified channels.",
        confidence_label="model_unvalidated",
    )
    
    combined_b = engine.synthesize(
        ai_output=ai_b,
        verifier_output=ver_b,
        raw_snippet=case_b["text"],
        normalized_length=len(case_b["text"]),
    )
    # Proves AI is essential for semantic social engineering!
    assert combined_b.verdict == "scam"
    assert any("SEMANTIC DETECTION" in r for r in combined_b.decision_rationale)
