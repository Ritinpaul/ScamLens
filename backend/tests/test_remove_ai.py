import pytest
from backend.app.services.deterministic_verifier import DeterministicVerifier
from backend.app.services.decision_engine import DecisionEngine
from backend.app.models.ai_schema import AiAnalysisOutput, AiVerdict, TacticItem
from backend.app.models.analysis_result import FinalVerdict

def test_remove_ai_proves_necessity():
    """
    Remove-AI Demonstration:
    Tests a subtle psychological intimidation/coercion scam (Digital Arrest pretext):
    No malicious URL, no OTP request, no credit card request, no UPI handle.
    """
    message = (
        "This is Senior Superintendent Sharma from Delhi Police Crime Branch. "
        "A formal judicial warrant has been issued against your national identity for unauthorized communications. "
        "You must remain in your room on video standby and follow our official instructions until clearance is granted. "
        "Do not consult third parties as this will be deemed contempt of judicial process."
    )

    # 1. Evaluate with Deterministic Verifier alone (AI removed)
    verifier = DeterministicVerifier()
    det_findings = verifier.verify(message)

    # Deterministic verifier finds no URLs, no OTP requests, no credentials, no payment IDs
    assert len(det_findings.urls) == 0
    assert det_findings.has_otp_request is False
    assert det_findings.has_credential_request is False
    assert det_findings.has_payment_request is False
    assert det_findings.has_shortened_url is False
    assert det_findings.has_ip_url is False

    engine = DecisionEngine()

    # Decision Engine WITHOUT AI:
    without_ai = engine.synthesize(
        ai_output=None,
        verifier_output=det_findings,
        raw_snippet=message,
        normalized_length=len(message),
        input_type="pasted_text"
    )

    # Without AI, the message cannot be safely recognized as a scam because no technical signatures fired
    assert without_ai.verdict != FinalVerdict.SCAM

    # 2. Evaluate WITH AI Semantic Understanding
    ai_output = AiAnalysisOutput(
        source="model",
        model_name="llama3:latest",
        verdict=AiVerdict.SCAM,
        summary="Classic digital arrest coercion: impersonating law enforcement to intimidate and isolate victim.",
        tactics=[
            TacticItem(type="authority_impersonation", evidence="Senior Superintendent Sharma from Delhi Police Crime Branch"),
            TacticItem(type="isolation_coercion", evidence="remain in your room on video standby ... do not consult third parties"),
            TacticItem(type="legal_intimidation", evidence="judicial warrant ... contempt of judicial process")
        ],
        requests=["Remain on video standby", "Do not speak to third parties"],
        entities=["Delhi Police Crime Branch"],
        urls=[],
        recommended_action="Do not comply. Genuine police officers do not conduct video trials or demand room isolation. Disconnect and report to cybercrime.gov.in.",
        confidence_label="model_unvalidated"
    )

    with_ai = engine.synthesize(
        ai_output=ai_output,
        verifier_output=det_findings,
        raw_snippet=message,
        normalized_length=len(message),
        input_type="pasted_text"
    )

    # With AI, the social engineering tactics are identified and the verdict correctly flags the scam
    assert with_ai.verdict == FinalVerdict.SCAM
    assert any("SEMANTIC DETECTION" in r for r in with_ai.decision_rationale)
    assert any("authority_impersonation" in t for t in with_ai.detected_manipulation_tactics)
    assert any("isolation_coercion" in t for t in with_ai.detected_manipulation_tactics)
