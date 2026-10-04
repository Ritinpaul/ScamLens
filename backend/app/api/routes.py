from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from backend.app.config import settings
from backend.app.core.normalizer import normalize_text
from backend.app.core.errors import ModelConnectionError, ModelInferenceError, SchemaValidationError, ImageProcessingError
from backend.app.services.ai_provider import OllamaProvider
from backend.app.services.deterministic_verifier import DeterministicVerifier
from backend.app.services.decision_engine import DecisionEngine
from backend.app.services.image_extractor import ImageTextExtractor
from backend.app.models.analysis_result import AnalysisResponse

router = APIRouter()

# Instantiate core services
ai_provider = OllamaProvider()
verifier = DeterministicVerifier()
decision_engine = DecisionEngine()
image_extractor = ImageTextExtractor()

class TextAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="The message or text to analyze for scam indicators")

class HealthStatus(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    model_provider: dict
    ocr_enabled: bool

@router.get("/health", response_model=HealthStatus)
async def health_check():
    """Health endpoint that queries backend and model status in real-time."""
    is_avail, msg = await ai_provider.is_available()
    return HealthStatus(
        status="ok",
        app="ScamLens",
        version="0.1.0",
        environment=settings.ENVIRONMENT,
        model_provider={
            "provider": "Ollama",
            "configured_model": settings.OLLAMA_MODEL,
            "base_url": settings.OLLAMA_BASE_URL,
            "available": is_avail,
            "status_message": msg,
        },
        ocr_enabled=settings.OCR_ENABLED,
    )

@router.post("/api/analyze/text", response_model=AnalysisResponse)
async def analyze_text_endpoint(req: TextAnalysisRequest):
    """Analyze a pasted message using both AI semantic understanding and deterministic security verification."""
    normalized = normalize_text(req.text)
    if not normalized:
        raise HTTPException(status_code=400, detail="Provided text is empty after normalization.")

    # 1. Deterministic verification
    verifier_findings = verifier.verify(normalized)

    # 2. AI Semantic analysis
    ai_output = None
    try:
        ai_output = await ai_provider.analyze_text(normalized)
    except ModelConnectionError as e:
        # Transparent error reporting: do not fake response, but explain to user
        raise HTTPException(
            status_code=503,
            detail=f"Local model runtime unavailable: {e.message}. Ensure Ollama is running at {settings.OLLAMA_BASE_URL}."
        )
    except (ModelInferenceError, SchemaValidationError) as e:
        raise HTTPException(
            status_code=502,
            detail=f"Model inference failed: {e.message}"
        )

    # 3. Decision synthesis
    final_result = decision_engine.synthesize(
        ai_output=ai_output,
        verifier_output=verifier_findings,
        normalized_length=len(normalized),
        input_type="text"
    )

    return final_result

@router.post("/api/analyze/image", response_model=AnalysisResponse)
async def analyze_image_endpoint(file: UploadFile = File(...)):
    """Extract text from an uploaded screenshot using local OCR and analyze it."""
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Uploaded file must be an image (PNG, JPEG, WebP, etc.).")

    try:
        contents = await file.read()
        extracted_text = image_extractor.extract_text_from_bytes(contents)
    except ImageProcessingError as e:
        raise HTTPException(status_code=422, detail=f"Image processing error: {e.message}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error extracting text from image: {str(e)}")

    if not extracted_text:
        raise HTTPException(status_code=400, detail="No readable text could be extracted from the uploaded screenshot.")

    normalized = normalize_text(extracted_text)

    # 1. Deterministic verification
    verifier_findings = verifier.verify(normalized)

    # 2. AI Semantic analysis
    ai_output = None
    try:
        ai_output = await ai_provider.analyze_text(normalized)
    except ModelConnectionError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Local model runtime unavailable: {e.message}. Ensure Ollama is running at {settings.OLLAMA_BASE_URL}."
        )
    except (ModelInferenceError, SchemaValidationError) as e:
        raise HTTPException(
            status_code=502,
            detail=f"Model inference failed: {e.message}"
        )

    # 3. Decision synthesis
    final_result = decision_engine.synthesize(
        ai_output=ai_output,
        verifier_output=verifier_findings,
        normalized_length=len(normalized),
        input_type="image"
    )

    return final_result
