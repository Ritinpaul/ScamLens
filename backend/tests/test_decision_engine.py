from backend.app.services.decision_engine import DecisionEngine
from backend.app.models.ai_schema import AiAnalysisOutput, AiVerdict, TacticItem
from backend.app.models.verifier_schema import VerifierOutput, DetectedSignal, SignalSeverity
from backend.app.models.analysis_result import FinalVerdict, ConfidenceRating

def test_safety_override_on_critical_signal():
    engine = DecisionEngine()
    
    ai_output = AiAnalysisOutput(
        verdict=AiVerdict.LIKELY_LEGITIMATE,
        summary="Message asks user to share verification code.",
        recommended_action="Follow instructions",
        confidence_label="model_unvalidated"
    )

    verifier_output = VerifierOutput(
        signals=[
            DetectedSignal(
                category="otp_harvesting",
                pattern_matched="Direct request to disclose OTP",
                snippet="share the OTP",
                severity=SignalSeverity.CRITICAL
            )
        ],
        has_otp_request=True,
        deterministic_risk_level="critical"
    )

    res = engine.synthesize(ai_output, verifier_output, raw_snippet="share the OTP", normalized_length=80)
    assert res.source == "decision_engine"
    assert res.ai_interpretation.source == "model"
    assert res.deterministic_findings.source == "deterministic"
    assert res.verdict == FinalVerdict.SCAM
    assert res.confidence == ConfidenceRating.HIGH
    assert any("SAFETY OVERRIDE" in r for r in res.decision_rationale)
    assert "CRITICAL WARNING" in res.recommended_action

def test_agreement_on_scam():
    engine = DecisionEngine()
    
    ai_output = AiAnalysisOutput(
        verdict=AiVerdict.SCAM,
        summary="Urgent power cut scam threatening disconnection.",
        tactics=[TacticItem(type="artificial_urgency", evidence="tonight at 9:30")],
        requests=["Call officer immediately"],
        recommended_action="Do not call.",
        confidence_label="model_unvalidated"
    )

    verifier_output = VerifierOutput(
        signals=[
            DetectedSignal(
                category="artificial_urgency",
                pattern_matched="Utility disconnection scam pretext",
                snippet="Electricity will be disconnected",
                severity=SignalSeverity.HIGH
            )
        ],
        has_urgency=True,
        deterministic_risk_level="high"
    )

    res = engine.synthesize(ai_output, verifier_output, raw_snippet="Electricity will be disconnected tonight", normalized_length=120)
    assert res.verdict == FinalVerdict.SCAM
    assert res.confidence == ConfidenceRating.HIGH
    assert any("AGREEMENT" in r for r in res.decision_rationale)

def test_semantic_detection_without_deterministic_triggers():
    engine = DecisionEngine()

    ai_output = AiAnalysisOutput(
        verdict=AiVerdict.SCAM,
        summary="Emotional manipulation asking for emergency medical transfer via untracked method.",
        tactics=[TacticItem(type="emotional_manipulation", evidence="in hospital dying")],
        recommended_action="Verify independently with family.",
        confidence_label="model_unvalidated"
    )

    verifier_output = VerifierOutput(
        signals=[],
        deterministic_risk_level="none"
    )

    res = engine.synthesize(ai_output, verifier_output, raw_snippet="Please help, in hospital dying", normalized_length=150)
    assert res.verdict == FinalVerdict.SCAM
    assert res.confidence == ConfidenceRating.MEDIUM
    assert any("SEMANTIC DETECTION" in r for r in res.decision_rationale)

def test_legitimate_clean_message():
    engine = DecisionEngine()

    ai_output = AiAnalysisOutput(
        verdict=AiVerdict.LIKELY_LEGITIMATE,
        summary="Ordinary greeting and scheduling dinner.",
        recommended_action="Respond normally.",
        confidence_label="model_unvalidated"
    )

    verifier_output = VerifierOutput(
        signals=[],
        deterministic_risk_level="none"
    )

    res = engine.synthesize(ai_output, verifier_output, raw_snippet="Hey dinner at 7?", normalized_length=50)
    assert res.verdict == FinalVerdict.LIKELY_LEGITIMATE
    assert res.confidence == ConfidenceRating.MEDIUM
    assert any("CLEAN SIGNALS" in r for r in res.decision_rationale)

def test_insufficient_evidence_short_input():
    engine = DecisionEngine()
    verifier_output = VerifierOutput(signals=[], deterministic_risk_level="none")

    res = engine.synthesize(ai_output=None, verifier_output=verifier_output, raw_snippet="Hi", normalized_length=5)
    assert res.verdict == FinalVerdict.INSUFFICIENT_EVIDENCE
    assert res.confidence == ConfidenceRating.LOW
