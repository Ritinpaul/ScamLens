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

class EvidenceTrace(BaseModel):
    input_type: str = Field(description="'pasted_text' or 'screenshot_ocr'")
    raw_input_snippet: str = Field(description="Initial characters of input for traceability")
    extracted_ocr_text: str | None = Field(default=None, description="Exact text extracted by OCR if image was analyzed")
    normalized_input_length: int = 0
    image_metadata: dict | None = Field(default=None, description="Image format, dimensions, line count")

class AnalysisResponse(BaseModel):
    source: str = Field(default="decision_engine", description="Identifier marking this top-level assessment as synthesized by the decision engine")
    verdict: FinalVerdict
    confidence: ConfidenceRating
    confidence_explanation: str
    plain_english_summary: str
    recommended_action: str
    
    # Layered Findings with Explicit Origins
    ai_interpretation: AiAnalysisOutput | None = Field(default=None, description="Semantic findings with source='model'")
    deterministic_findings: VerifierOutput = Field(description="Ground-truth findings with source='deterministic'")
    
    # Explainability & Provenance
    decision_rationale: list[str] = Field(
        default_factory=list,
        description="Transparent rules and reasoning explaining how the final verdict was reached"
    )
    detected_manipulation_tactics: list[str] = Field(default_factory=list)
    extracted_evidence: list[str] = Field(default_factory=list)
    
    # Traceability
    evidence_trace: EvidenceTrace
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
