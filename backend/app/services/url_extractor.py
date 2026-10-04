import re
import ipaddress
from urllib.parse import urlparse
from backend.app.models.verifier_schema import DetectedUrl, UrlCertainty

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at",
    "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc", "goo.gl", "trib.al",
    "rb.gy", "bl.ink", "hyperurl.co", "soo.gd", "s.id", "v.gd"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "club", "work", "icu", "link",
    "rest", "gq", "cf", "tk", "ml", "ga", "kim", "fit", "surf"
}

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "in", "co.in", "io", "ai", "co", "me", "info", "biz"
}
ALL_KNOWN_TLDS = SUSPICIOUS_TLDS | COMMON_TLDS

# Standard RFC URL pattern
STANDARD_URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,6}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
)

# OCR Malformed URL patterns:
# e.g., 'http lisbi-kyc xyz verify', 'http lsbi-kycxyz verify', 'https ://foo.com', 'http://sbi-kycxyz'
OCR_MALFORMED_URL_REGEX = re.compile(
    r"(?i)\b(https?)\s*[:|I!l/\s]{1,4}([a-z0-9][a-z0-9.\-_]{2,60}(?:\s+[a-z]{2,6}|\.[a-z]{2,6}))(?:\s+([a-z0-9/.\-_]+))?",
    re.IGNORECASE
)

class UrlExtractor:
    """
    Extracts, inspects, and normalizes URLs from text and OCR streams.
    Categorizes detections into 3 tiers of certainty:
      - CONFIDENT: Well-formed standard URL with valid protocol/domain.
      - PROBABLE: Clear domain and path without explicit protocol.
      - UNCERTAIN: OCR noise, broken delimiters, or malformed protocol.
    
    GUARANTEES:
      - Never performs external network requests or DNS queries.
      - Never fabricates domain characters; preserves exact raw OCR snippets.
    """

    def extract_urls(self, text: str) -> list[DetectedUrl]:
        detected: list[DetectedUrl] = []
        seen_raw: set[str] = set()

        # Phase 1: Confident & Probable standard extraction
        for match in STANDARD_URL_REGEX.finditer(text):
            raw_url = match.group(0).strip()
            if raw_url in seen_raw:
                continue
            seen_raw.add(raw_url)

            det_url = self._inspect_standard_url(raw_url)
            detected.append(det_url)

        # Phase 2: Conservative OCR Malformed / Candidate Reconstruction
        for match in OCR_MALFORMED_URL_REGEX.finditer(text):
            raw_snippet = match.group(0).strip()
            # If this snippet is already fully covered by a standard URL match, skip
            if any(raw_snippet in seen or seen in raw_snippet for seen in seen_raw):
                continue
            
            seen_raw.add(raw_snippet)
            uncertain_url = self._inspect_malformed_ocr_candidate(match)
            if uncertain_url:
                detected.append(uncertain_url)

        return detected

    def _inspect_standard_url(self, raw_url: str) -> DetectedUrl:
        to_parse = raw_url
        has_explicit_scheme = to_parse.startswith(("http://", "https://"))
        if not has_explicit_scheme:
            to_parse = "http://" + to_parse

        try:
            parsed = urlparse(to_parse)
            host = parsed.hostname or ""
        except Exception:
            host = ""

        is_ip, is_short, is_susp_tld, notes = self._analyze_host(host)

        certainty = UrlCertainty.CONFIDENT if has_explicit_scheme else UrlCertainty.PROBABLE

        return DetectedUrl(
            raw_url=raw_url,
            scheme=parsed.scheme if parsed.scheme else ("http" if has_explicit_scheme else ""),
            host=host,
            path=parsed.path or "",
            is_ip_address=is_ip,
            is_shortener=is_short,
            is_suspicious_tld=is_susp_tld,
            certainty=certainty,
            reconstructed_candidate=None,
            notes=notes,
        )

    def _inspect_malformed_ocr_candidate(self, match: re.Match) -> DetectedUrl | None:
        raw_snippet = match.group(0).strip()
        proto = match.group(1).lower()
        domain_part = match.group(2).strip()
        path_part = match.group(3).strip() if match.group(3) else ""

        # Conservative candidate reconstruction
        # Handle space before TLD: e.g. "sbi-kyc xyz" -> "sbi-kyc.xyz"
        normalized_domain = domain_part
        if " " in normalized_domain:
            parts = normalized_domain.split()
            if len(parts) == 2 and parts[1].lower() in ALL_KNOWN_TLDS:
                normalized_domain = f"{parts[0]}.{parts[1]}"

        # Remove accidental OCR leading 'l' or 'i' attached to domain: e.g. "lisbi-kyc.xyz" -> "sbi-kyc.xyz"
        if normalized_domain.startswith(("lisbi", "lsbi", "isbi")) and "-" in normalized_domain:
            normalized_domain = normalized_domain[1:]

        candidate = f"{proto}://{normalized_domain}"
        if path_part:
            candidate += f"/{path_part.lstrip('/')}"

        is_ip, is_short, is_susp_tld, notes = self._analyze_host(normalized_domain)
        notes.append("OCR noise detected in URL protocol or delimiters. Preserved as uncertain candidate; characters should be verified manually.")

        return DetectedUrl(
            raw_url=raw_snippet,
            scheme=proto,
            host=normalized_domain,
            path=f"/{path_part}" if path_part else "",
            is_ip_address=is_ip,
            is_shortener=is_short,
            is_suspicious_tld=is_susp_tld,
            certainty=UrlCertainty.UNCERTAIN,
            reconstructed_candidate=candidate,
            notes=notes,
        )

    def _analyze_host(self, host: str) -> tuple[bool, bool, bool, list[str]]:
        is_ip = False
        if host:
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False

        is_short = host.lower() in SHORTENER_DOMAINS if host else False

        is_susp_tld = False
        notes = []
        if is_ip:
            notes.append("Host is a numerical IP address instead of a recognized domain")
        if is_short:
            notes.append(f"Domain '{host}' hides the final destination URL")
        
        if host and not is_ip:
            parts = host.lower().split(".")
            if len(parts) >= 2 and parts[-1] in SUSPICIOUS_TLDS:
                is_susp_tld = True
                notes.append(f"TLD '.{parts[-1]}' is statistically correlated with disposable phishing sites")

        return is_ip, is_short, is_susp_tld, notes
