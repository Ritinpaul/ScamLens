import io
import logging
from PIL import Image
from backend.app.config import settings
from backend.app.core.errors import ImageProcessingError

logger = logging.getLogger(__name__)

class ImageTextExtractor:
    """Extracts text from screenshots using local OCR."""

    def __init__(self):
        self._reader = None

    def _get_reader(self):
        if self._reader is None:
            if not settings.OCR_ENABLED:
                raise ImageProcessingError("OCR processing is disabled in configuration.")
            try:
                import easyocr
                # Initialize EasyOCR with CPU to avoid VRAM contention with Ollama on 4GB GPUs
                self._reader = easyocr.Reader(settings.OCR_LANGUAGES, gpu=False)
            except Exception as e:
                raise ImageProcessingError(f"Failed to initialize EasyOCR engine: {str(e)}") from e
        return self._reader

    def extract_text_from_bytes(self, image_bytes: bytes) -> str:
        """Process raw image bytes and return extracted textual content."""
        if not image_bytes:
            raise ImageProcessingError("Received empty image data.")

        try:
            # Validate image integrity with PIL
            image = Image.open(io.BytesIO(image_bytes))
            image.verify()
            
            # Re-open for actual processing (verify closes stream in PIL)
            image = Image.open(io.BytesIO(image_bytes))
        except Exception as e:
            raise ImageProcessingError(f"Invalid or corrupted image format: {str(e)}") from e

        reader = self._get_reader()
        try:
            # EasyOCR can accept image bytes or numpy array
            results = reader.readtext(image_bytes, detail=0)
            extracted_text = "\n".join(results)
            return extracted_text.strip()
        except Exception as e:
            raise ImageProcessingError(f"Error during OCR text extraction: {str(e)}") from e
