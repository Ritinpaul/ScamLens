from enum import Enum
from pydantic import BaseModel, Field

class SignalSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class DetectedUrl(BaseModel):
    raw_url: str
    scheme: str = ""
    host: str = ""
    path: str = ""
    is_ip_address: bool = False
    is_shortener: bool = False
    is_suspicious_tld: bool = False
    notes: list[str] = Field(default_factory=list)

class DetectedSignal(BaseModel):
    category: str = Field(description="Signal category e.g., otp_harvesting, credential_solicitation, payment_pressure, artificial_urgency, suspicious_url")
    pattern_matched: str = Field(description="The underlying security rule or indicator triggered")
    snippet: str = Field(description="Exact snippet from the normalized text that triggered the rule")
    severity: SignalSeverity = Field(description="Severity tier of this finding")

class VerifierOutput(BaseModel):
    source: str = Field(default="deterministic", description="Identifier marking this block as deterministic ground-truth verification")
    urls: list[DetectedUrl] = Field(default_factory=list)
    signals: list[DetectedSignal] = Field(default_factory=list)
    has_otp_request: bool = False
    has_credential_request: bool = False
    has_payment_request: bool = False
    has_shortened_url: bool = False
    has_ip_url: bool = False
    has_urgency: bool = False
    deterministic_risk_level: str = "none"  # "critical", "high", "medium", "low", "none"
