from enum import Enum
from pydantic import BaseModel, Field

class AiVerdict(str, Enum):
    SCAM = "scam"
    SUSPICIOUS = "suspicious"
    LIKELY_LEGITIMATE = "likely_legitimate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

class TacticItem(BaseModel):
    type: str = Field(description="The manipulation tactic (e.g., authority_impersonation, artificial_urgency, fear_threat, financial_bait)")
    evidence: str = Field(description="Direct snippet or textual reason from the message supporting this tactic")

class AiAnalysisOutput(BaseModel):
    verdict: AiVerdict = Field(description="Preliminary semantic verdict from the model")
    summary: str = Field(description="Plain-English explanation of what the message is attempting to achieve")
    tactics: list[TacticItem] = Field(default_factory=list, description="Manipulation or social engineering tactics identified")
    requests: list[str] = Field(default_factory=list, description="Specific actions requested of the victim (e.g. click link, install APK, send OTP)")
    entities: list[str] = Field(default_factory=list, description="Organizations, banks, or brands claimed to be involved")
    urls: list[str] = Field(default_factory=list, description="URLs or domains extracted by the model")
    recommended_action: str = Field(description="Direct, safe recommendation for the recipient")
    uncertainty_reason: str = Field(default="", description="Honest statement of what information was ambiguous or missing")
    confidence_label: str = Field(
        default="model_unvalidated",
        description="Explicit notice that model confidence is qualitative and not scientifically calibrated"
    )
