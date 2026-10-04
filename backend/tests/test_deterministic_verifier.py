from backend.app.services.deterministic_verifier import DeterministicVerifier
from backend.app.models.verifier_schema import SignalSeverity

def test_url_extraction_standard():
    verifier = DeterministicVerifier()
    text = "Visit https://google.com and http://example.org/test for details."
    out = verifier.verify(text)
    assert len(out.urls) == 2
    hosts = [u.host for u in out.urls]
    assert "google.com" in hosts
    assert "example.org" in hosts

def test_shortened_url_detection():
    verifier = DeterministicVerifier()
    text = "Claim your lottery prize now at https://bit.ly/claim-prize-3829"
    out = verifier.verify(text)
    assert out.has_shortened_url is True
    assert any(s.category == "suspicious_url" and s.pattern_matched == "url_shortener_evasion" for s in out.signals)

def test_ip_address_url_detection():
    verifier = DeterministicVerifier()
    text = "Your bank account suspended. Update at http://192.168.1.50/login"
    out = verifier.verify(text)
    assert out.has_ip_url is True
    assert any(s.pattern_matched == "raw_ip_address_host" for s in out.signals)
    assert out.deterministic_risk_level == "critical"

def test_otp_request_detection():
    verifier = DeterministicVerifier()
    text = "Dear customer, please share the OTP sent to your phone to complete refund."
    out = verifier.verify(text)
    assert out.has_otp_request is True
    assert any(s.category == "otp_harvesting" for s in out.signals)
    assert out.deterministic_risk_level == "critical"

def test_credential_request_detection():
    verifier = DeterministicVerifier()
    text = "Mandatory KYC update: Enter your netbanking password and CVV to prevent deactivation."
    out = verifier.verify(text)
    assert out.has_credential_request is True
    assert any(s.category == "credential_solicitation" for s in out.signals)
    assert out.deterministic_risk_level == "critical"

def test_payment_upi_detection():
    verifier = DeterministicVerifier()
    text = "Send registration fee of Rs. 500 to hr.recruitment@okaxis to confirm your interview."
    out = verifier.verify(text)
    assert out.has_payment_request is True
    assert any(s.category == "payment_pressure" and s.pattern_matched == "direct_upi_address" for s in out.signals)

def test_urgency_detection():
    verifier = DeterministicVerifier()
    text = "Electricity power cut tonight at 9:30 PM due to unpaid bill. Pay immediately."
    out = verifier.verify(text)
    assert out.has_urgency is True
    assert any(s.category == "artificial_urgency" for s in out.signals)

def test_brand_domain_mismatch():
    verifier = DeterministicVerifier()
    text = "State Bank of India SBI alert: Update KYC at http://sbi-kyc-verify.top/login"
    out = verifier.verify(text)
    assert any(s.category == "impersonation_mismatch" for s in out.signals)
    assert out.deterministic_risk_level == "critical"

def test_clean_message_no_signals():
    verifier = DeterministicVerifier()
    text = "Hey are we still meeting for lunch tomorrow at 1 PM?"
    out = verifier.verify(text)
    assert len(out.signals) == 0
    assert out.deterministic_risk_level == "none"
