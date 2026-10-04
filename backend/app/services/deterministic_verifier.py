import re
import ipaddress
from urllib.parse import urlparse
from backend.app.models.verifier_schema import (
    VerifierOutput,
    DetectedUrl,
    DetectedSignal,
    SignalSeverity,
)

# Known URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at",
    "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc", "goo.gl", "trib.al",
    "rb.gy", "bl.ink", "hyperurl.co", "soo.gd", "s.id", "v.gd"
}

# Suspicious TLDs frequently abused in cheap phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "club", "work", "icu", "link",
    "rest", "gq", "cf", "tk", "ml", "ga", "kim", "fit", "surf"
}

# Regex for URL extraction
URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
)

# Regex for Indian UPI IDs
UPI_REGEX = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,256}@(okhdfcbank|okaxis|oksbi|okicici|ybl|paytm|upi|apl|axl|ibl|barodampay|idbi|aubank|kotak)\b",
    re.IGNORECASE
)

# OTP harvesting indicators
OTP_PATTERNS = [
    (r"\b(?:share|send|forward|tell|give)\s+(?:the\s+)?(?:otp|one\s*time\s*password|verification\s*code|6\s*digit\s*code)\b", "Direct request to disclose OTP/verification code", SignalSeverity.CRITICAL),
    (r"\b(?:otp|code)\s+(?:sent\s+to\s+your\s+phone|received\s+on\s+sms)\b", "Reference to an incoming authentication code", SignalSeverity.HIGH),
    (r"\b(?:enter|submit)\s+(?:the\s+)?otp\s+to\s+(?:receive|claim|credit|accept)\b", "Classic reverse-OTP / credit deception pattern", SignalSeverity.CRITICAL),
]

# Credential harvesting indicators
CREDENTIAL_PATTERNS = [
    (r"\b(?:enter|provide|update|verify|confirm)\s+(?:your\s+)?(?:netbanking\s+password|login\s+password|atm\s+pin|mpin|cvv|card\s+number)\b", "Request for banking secrets/passwords/PIN", SignalSeverity.CRITICAL),
    (r"\b(?:cvv|card\s+verification\s+value)\b", "Card security code mention", SignalSeverity.HIGH),
    (r"\b(?:pan\s*card\s*number|aadhaar\s*number|aadhar\s*number)\s+(?:update|verification|mandatory)\b", "Government identity credential solicitation", SignalSeverity.HIGH),
]

# Payment / Financial manipulation indicators
PAYMENT_PATTERNS = [
    (r"\b(?:scan\s+(?:this\s+)?qr\s*(?:code)?\s*to\s*(?:receive|get|claim)\b)", "Reverse QR Code deception (scanning QR pays, never receives)", SignalSeverity.CRITICAL),
    (r"\b(?:pay|send|transfer)\s+(?:rs\.?|inr|₹|\$)\s*\d+", "Explicit money transfer solicitation", SignalSeverity.HIGH),
    (r"\b(?:processing\s*fee|registration\s*fee|refundable\s*deposit|customs\s*duty|courier\s*charge)\b", "Advance-fee scam pattern", SignalSeverity.HIGH),
    (r"\b(?:lottery|jackpot|won\s+(?:rs\.?|inr|₹|\$)|congratulations\s+you\s+won)\b", "Unsolicited prize / lottery bait", SignalSeverity.HIGH),
]

# Urgency / Threat indicators
URGENCY_PATTERNS = [
    (r"\b(?:within\s+(?:24|12|2|1)\s*hours?|immediately|tonight\s+at\s+\d+|by\s+midnight)\b", "Time-pressure coercion", SignalSeverity.HIGH),
    (r"\b(?:electricity|power|light)\s+(?:will\s+be\s+disconnected|power\s+cut)\b", "Utility disconnection scam pretext", SignalSeverity.HIGH),
    (r"\b(?:account|sim|card|services?)\s+(?:will\s+be\s+blocked|suspended|deactivated|terminated|closed)\b", "Service suspension threat", SignalSeverity.HIGH),
    (r"\b(?:arrest\s*warrant|legal\s*action|police\s*case|cbi|ed\s*officer|court\s*order)\b", "Legal/police intimidation coercion", SignalSeverity.CRITICAL),
    (r"\b(?:kyc\s*(?:update|expired|pending|verification|suspended))\b", "KYC suspension pretext", SignalSeverity.HIGH),
]

# Known institutional brands often impersonated
BRAND_KEYWORDS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "statebankofindia.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "netflix": ["netflix.com"],
    "india post": ["indiapost.gov.in"],
    "fedex": ["fedex.com"],
}

class DeterministicVerifier:
    """Performs explainable, deterministic signature and pattern inspection."""

    def verify(self, text: str) -> VerifierOutput:
        urls = self._extract_and_inspect_urls(text)
        signals: list[DetectedSignal] = []

        # 1. URL signals
        for u in urls:
            if u.is_ip_address:
                signals.append(DetectedSignal(
                    category="suspicious_url",
                    pattern_matched="raw_ip_address_host",
                    snippet=u.raw_url,
                    severity=SignalSeverity.CRITICAL,
                ))
            if u.is_shortener:
                signals.append(DetectedSignal(
                    category="suspicious_url",
                    pattern_matched="url_shortener_evasion",
                    snippet=u.raw_url,
                    severity=SignalSeverity.HIGH,
                ))
            if u.is_suspicious_tld:
                signals.append(DetectedSignal(
                    category="suspicious_url",
                    pattern_matched="suspicious_tld",
                    snippet=u.raw_url,
                    severity=SignalSeverity.HIGH,
                ))
            if u.scheme == "http":
                signals.append(DetectedSignal(
                    category="suspicious_url",
                    pattern_matched="unencrypted_http_scheme",
                    snippet=u.raw_url,
                    severity=SignalSeverity.MEDIUM,
                ))

        # 2. OTP signals
        has_otp = False
        for pattern, desc, sev in OTP_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                has_otp = True
                signals.append(DetectedSignal(
                    category="otp_harvesting",
                    pattern_matched=desc,
                    snippet=match.group(0),
                    severity=sev,
                ))

        # 3. Credential solicitation
        has_credentials = False
        for pattern, desc, sev in CREDENTIAL_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                has_credentials = True
                signals.append(DetectedSignal(
                    category="credential_solicitation",
                    pattern_matched=desc,
                    snippet=match.group(0),
                    severity=sev,
                ))

        # 4. Payment / UPI solicitation
        has_payment = False
        upi_match = UPI_REGEX.search(text)
        if upi_match:
            has_payment = True
            signals.append(DetectedSignal(
                category="payment_pressure",
                pattern_matched="direct_upi_address",
                snippet=upi_match.group(0),
                severity=SignalSeverity.HIGH,
            ))

        for pattern, desc, sev in PAYMENT_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                has_payment = True
                signals.append(DetectedSignal(
                    category="payment_pressure",
                    pattern_matched=desc,
                    snippet=match.group(0),
                    severity=sev,
                ))

        # 5. Urgency & Threats
        has_urgency = False
        for pattern, desc, sev in URGENCY_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                has_urgency = True
                signals.append(DetectedSignal(
                    category="artificial_urgency",
                    pattern_matched=desc,
                    snippet=match.group(0),
                    severity=sev,
                ))

        # 6. Brand vs URL Domain Mismatch
        for brand, legit_domains in BRAND_KEYWORDS.items():
            if re.search(rf"\b{re.escape(brand)}\b", text, re.IGNORECASE):
                # Brand is claimed; verify if any URLs belong to legitimate domain
                for u in urls:
                    host = u.host.lower()
                    if host and not any(host == ld or host.endswith("." + ld) for ld in legit_domains):
                        signals.append(DetectedSignal(
                            category="impersonation_mismatch",
                            pattern_matched=f"claimed_brand_{brand}_mismatched_domain_{host}",
                            snippet=f"Claimed brand '{brand}' with link '{u.raw_url}'",
                            severity=SignalSeverity.CRITICAL,
                        ))

        # Determine overall deterministic risk tier
        risk_level = self._compute_risk_level(signals)

        return VerifierOutput(
            urls=urls,
            signals=signals,
            has_otp_request=has_otp,
            has_credential_request=has_credentials,
            has_payment_request=has_payment,
            has_shortened_url=any(u.is_shortener for u in urls),
            has_ip_url=any(u.is_ip_address for u in urls),
            has_urgency=has_urgency,
            deterministic_risk_level=risk_level,
        )

    def _extract_and_inspect_urls(self, text: str) -> list[DetectedUrl]:
        detected: list[DetectedUrl] = []
        raw_matches = URL_REGEX.findall(text)

        for match in raw_matches:
            raw_url = match[0] if isinstance(match, tuple) else match
            raw_url = raw_url.strip()

            # Ensure valid parseable scheme
            to_parse = raw_url
            if not to_parse.startswith(("http://", "https://")):
                to_parse = "http://" + to_parse

            try:
                parsed = urlparse(to_parse)
                host = parsed.hostname or ""
            except Exception:
                host = ""

            # Check if host is raw IP
            is_ip = False
            if host:
                try:
                    ipaddress.ip_address(host)
                    is_ip = True
                except ValueError:
                    is_ip = False

            # Check if domain is known shortener
            is_short = host.lower() in SHORTENER_DOMAINS if host else False

            # Check TLD
            is_susp_tld = False
            if host and not is_ip:
                parts = host.lower().split(".")
                if len(parts) >= 2 and parts[-1] in SUSPICIOUS_TLDS:
                    is_susp_tld = True

            notes = []
            if is_ip:
                notes.append("Host is a numerical IP address instead of a recognized domain")
            if is_short:
                notes.append(f"Domain '{host}' hides the final destination URL")
            if is_susp_tld:
                notes.append(f"TLD '.{parts[-1]}' is statistically correlated with disposable phishing sites")

            detected.append(DetectedUrl(
                raw_url=raw_url,
                scheme=parsed.scheme if parsed.scheme else "",
                host=host,
                path=parsed.path or "",
                is_ip_address=is_ip,
                is_shortener=is_short,
                is_suspicious_tld=is_susp_tld,
                notes=notes,
            ))

        return detected

    def _compute_risk_level(self, signals: list[DetectedSignal]) -> str:
        severities = {s.severity for s in signals}
        if SignalSeverity.CRITICAL in severities:
            return "critical"
        if SignalSeverity.HIGH in severities:
            return "high"
        if SignalSeverity.MEDIUM in severities:
            return "medium"
        if SignalSeverity.LOW in severities:
            return "low"
        return "none"
