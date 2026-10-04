from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from backend.app.models.ai_schema import AiAnalysisOutput
from backend.app.models.verifier_schema import VerifierOutput

class FinalVerdict(str, Enum):
    SCAM = "scam"
    SUSPICIOUS = "suspicious"
    LIKELY_LEGITIMATE = "likely_legitimate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

class ConfidenceRating(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"

class AnalysisResponse(BaseModel):
    verdict: FinalVerdict
    confidence: ConfidenceRating
    confidence_explanation: str
    plain_english_summary: str
    recommended_action: str
    
    # Layered Findings
    ai_findings: AiAnalysisOutput | None = None
    deterministic_findings: VerifierOutput
    
    # Explainability & Provenance
    decision_rationale: list[str] = Field(
        default_factory=list,
        description="Transparent rules and reasoning explaining how the final verdict was reached"
    )
    detected_manipulation_tactics: list[str] = Field(default_factory=list)
    extracted_evidence: list[str] = Field(default_factory=list)
    
    # Metadata
    input_type: str = "text"  # "text" or "image"
    normalized_input_length: int = 0
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
