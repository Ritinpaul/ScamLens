class ScamLensError(Exception):
    """Base exception for ScamLens application."""
    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

class ModelConnectionError(ScamLensError):
    """Raised when the local inference runtime (e.g. Ollama) cannot be reached."""
    pass

class ModelInferenceError(ScamLensError):
    """Raised when the model runtime encounters an error during inference."""
    pass

class SchemaValidationError(ScamLensError):
    """Raised when the model's output fails to conform to the required JSON schema."""
    pass

class NormalizationError(ScamLensError):
    """Raised when input normalization encounters unparseable or corrupted data."""
    pass

class ImageProcessingError(ScamLensError):
    """Raised when an image cannot be processed or decoded for OCR."""
    pass
