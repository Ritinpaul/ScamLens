import pytest
from backend.app.models.ai_schema import AiAnalysisOutput, AiVerdict, TacticItem
from backend.app.models.analysis_result import FinalVerdict
from backend.app.models.verifier_schema import SignalSeverity
from backend.app.services.deterministic_verifier import DeterministicVerifier
from backend.app.services.decision_engine import DecisionEngine

def test_pair_1_otp_context():
    """
    Pair 1 — OTP
    Legitimate: "Your OTP for login is 123456. DO NOT share this OTP with anyone."
    Scam: "Support team: send us the OTP you received so we can restore your account."
    """
    verifier = DeterministicVerifier()
    engine = DecisionEngine()

    legit_text = "Your OTP for login is 123456. DO NOT share this OTP with anyone."
    legit_ver = verifier.verify(legit_text)
    # The negative warning must prevent direct OTP harvest flag
    assert legit_ver.has_otp_request is False
    assert legit_ver.deterministic_risk_level == "none"

    # Contextual decision engine verification:
    # Model delivering code with protective warning
    legit_ai = AiAnalysisOutput(
        verdict=AiVerdict.LIKELY_LEGITIMATE,
        summary="Routine one-time password notification with explicit negative sharing warning.",
        tactics=[],
        requests=[],
        entities=["Service"],
        urls=[],
        recommended_action="Do not share this code with anyone.",
        contains_negative_security_warning=True,
        requests_secret_disclosure=False,
    )
    legit_decision = engine.synthesize(legit_ai, legit_ver, legit_text, len(legit_text))
    assert legit_decision.verdict == FinalVerdict.LIKELY_LEGITIMATE

    # Even if model was hyper-vigilant and returned scam/suspicious,
    # contextual engine recognizes protective warning + zero dangerous requests:
    hyper_vigilant_ai = AiAnalysisOutput(
        verdict=AiVerdict.SCAM,
        summary="Message contains OTP.",
        tactics=[TacticItem(type="credential_mention", evidence="OTP mentioned")],
        requests=[],
        entities=[],
        urls=[],
        recommended_action="Exercise caution",
        contains_negative_security_warning=True,
        requests_secret_disclosure=False,
    )
    calibrated_decision = engine.synthesize(hyper_vigilant_ai, legit_ver, legit_text, len(legit_text))
    assert calibrated_decision.verdict == FinalVerdict.LIKELY_LEGITIMATE

    # Scam counterpart
    scam_text = "Support team: send us the OTP you received so we can restore your account."
    scam_ver = verifier.verify(scam_text)
    assert scam_ver.has_otp_request is True
    assert scam_ver.deterministic_risk_level == "critical"

    scam_ai = AiAnalysisOutput(
        verdict=AiVerdict.SCAM,
        summary="Attacker impersonating support requesting 2FA security code.",
        tactics=[TacticItem(type="authority_impersonation", evidence="Support team")],
        requests=["send us the OTP"],
        entities=["Support team"],
        urls=[],
        recommended_action="Do not share OTP.",
        requests_secret_disclosure=True,
    )
    scam_decision = engine.synthesize(scam_ai, scam_ver, scam_text, len(scam_text))
    assert scam_decision.verdict == FinalVerdict.SCAM

def test_pair_2_electricity_context():
    """
    Pair 2 — Electricity
    Legitimate: "Your electricity bill is due on October 8. Pay before the due date to avoid late fees."
    Scam: "Your electricity will be disconnected tonight. Call immediately and pay through this number."
    """
    verifier = DeterministicVerifier()
    engine = DecisionEngine()

    legit_text = "Your electricity bill is due on October 8. Pay before the due date to avoid late fees."
    legit_ver = verifier.verify(legit_text)
    assert legit_ver.has_urgency is False
    assert legit_ver.deterministic_risk_level == "none"

    legit_ai = AiAnalysisOutput(
        verdict=AiVerdict.LIKELY_LEGITIMATE,
        summary="Standard routine utility bill reminder with normal due date.",
        tactics=[],
        requests=["pay before due date"],
        entities=["Electricity Board"],
        urls=[],
        recommended_action="Pay via official portal.",
        contains_normal_due_date_language=True,
        uses_coercive_urgency=False,
    )
    legit_decision = engine.synthesize(legit_ai, legit_ver, legit_text, len(legit_text))
    assert legit_decision.verdict == FinalVerdict.LIKELY_LEGITIMATE

    # Scam counterpart
    scam_text = "Your electricity will be disconnected tonight. Call immediately and pay through this number."
    scam_ver = verifier.verify(scam_text)
    assert scam_ver.has_urgency is True
    assert scam_ver.deterministic_risk_level in ("high", "critical")

    scam_ai = AiAnalysisOutput(
        verdict=AiVerdict.SCAM,
        summary="Panic-inducing disconnection scam threatening immediate power cut.",
        tactics=[TacticItem(type="fear_threat", evidence="disconnected tonight")],
        requests=["call immediately and pay"],
        entities=["Electricity Office"],
        urls=[],
        recommended_action="Do not call.",
        uses_coercive_urgency=True,
        requests_payment=True,
    )
    scam_decision = engine.synthesize(scam_ai, scam_ver, scam_text, len(scam_text))
    assert scam_decision.verdict == FinalVerdict.SCAM

def test_pair_3_security_notification_context():
    """
    Pair 3 — Security notification
    Legitimate: "We detected a login to your account. If this wasn't you, review your account security."
    Scam: "Your account has been compromised. Call this support number immediately and provide your verification code."
    """
    verifier = DeterministicVerifier()
    engine = DecisionEngine()

    legit_text = "We detected a login to your account. If this wasn't you, review your account security."
    legit_ver = verifier.verify(legit_text)
    assert len(legit_ver.signals) == 0
    assert legit_ver.deterministic_risk_level == "none"

    legit_ai = AiAnalysisOutput(
        verdict=AiVerdict.LIKELY_LEGITIMATE,
        summary="Informational security alert notifying user of recent login.",
        tactics=[],
        requests=["review account security"],
        entities=["Service"],
        urls=[],
        recommended_action="Review official security settings if unrecognized.",
        contains_transaction_notification=True,
        requests_secret_disclosure=False,
    )
    legit_decision = engine.synthesize(legit_ai, legit_ver, legit_text, len(legit_text))
    assert legit_decision.verdict == FinalVerdict.LIKELY_LEGITIMATE

    # Scam counterpart
    scam_text = "Your account has been compromised. Call this support number immediately and provide your verification code."
    scam_ver = verifier.verify(scam_text)
    assert scam_ver.has_urgency is True
    assert scam_ver.has_otp_request is True
    assert scam_ver.deterministic_risk_level == "critical"

    scam_ai = AiAnalysisOutput(
        verdict=AiVerdict.SCAM,
        summary="Phishing attempt soliciting verification code over the phone.",
        tactics=[TacticItem(type="artificial_urgency", evidence="immediately")],
        requests=["call support", "provide verification code"],
        entities=["Support"],
        urls=[],
        recommended_action="Do not call or provide verification code.",
        requests_secret_disclosure=True,
        uses_coercive_urgency=True,
    )
    scam_decision = engine.synthesize(scam_ai, scam_ver, scam_text, len(scam_text))
    assert scam_decision.verdict == FinalVerdict.SCAM

def test_pair_4_payment_context():
    """
    Pair 4 — Payment
    Legitimate: "Your SBI account was debited ₹500 for your recent transaction."
    Scam: "Your refund is pending. Scan this QR code to receive the refund."
    """
    verifier = DeterministicVerifier()
    engine = DecisionEngine()

    legit_text = "Your SBI account was debited ₹500 for your recent transaction."
    legit_ver = verifier.verify(legit_text)
    # Informational debit notification must not trigger payment pressure
    assert legit_ver.has_payment_request is False
    assert legit_ver.deterministic_risk_level == "none"

    legit_ai = AiAnalysisOutput(
        verdict=AiVerdict.LIKELY_LEGITIMATE,
        summary="Informational bank debit notification for recent transaction.",
        tactics=[],
        requests=[],
        entities=["SBI"],
        urls=[],
        recommended_action="Verify transaction against your account statement.",
        contains_transaction_notification=True,
        requests_payment=False,
    )
    legit_decision = engine.synthesize(legit_ai, legit_ver, legit_text, len(legit_text))
    assert legit_decision.verdict == FinalVerdict.LIKELY_LEGITIMATE

    # Scam counterpart: Reverse QR scam
    scam_text = "Your refund is pending. Scan this QR code to receive the refund."
    scam_ver = verifier.verify(scam_text)
    assert scam_ver.has_payment_request is True
    assert scam_ver.deterministic_risk_level == "critical"

    scam_ai = AiAnalysisOutput(
        verdict=AiVerdict.SCAM,
        summary="Reverse QR code scam claiming scanning QR receives a refund.",
        tactics=[TacticItem(type="reverse_payment_deception", evidence="scan QR code to receive")],
        requests=["scan QR code"],
        entities=[],
        urls=[],
        recommended_action="Do not scan QR code; scanning QR pays money.",
        requests_payment=True,
    )
    scam_decision = engine.synthesize(scam_ai, scam_ver, scam_text, len(scam_text))
    assert scam_decision.verdict == FinalVerdict.SCAM
