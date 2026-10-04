import io
import logging
import re
from PIL import Image, ImageEnhance
from backend.app.config import settings
from backend.app.core.errors import ImageProcessingError

logger = logging.getLogger(__name__)

# Max upload size: 10 MB
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024

# Magic byte signatures
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
WEBP_MAGIC_RIFF = b"RIFF"
WEBP_MAGIC_WEBP = b"WEBP"

MIN_DIMENSION = 50
MAX_DIMENSION = 8000

class ImageTextExtractor:
    """Validates, preprocesses, and extracts text from screenshots using local OCR."""

    def __init__(self):
        self._reader = None

    def _get_reader(self):
        if self._reader is None:
            if not settings.OCR_ENABLED:
                raise ImageProcessingError("OCR processing is disabled in configuration.")
            try:
                import easyocr
                # Use CPU for OCR to avoid VRAM contention with the local LLM on 4GB GPUs
                self._reader = easyocr.Reader(settings.OCR_LANGUAGES, gpu=False)
            except Exception as e:
                raise ImageProcessingError(f"Failed to initialize EasyOCR engine: {str(e)}") from e
        return self._reader

    def validate_image(self, image_bytes: bytes) -> tuple[str, int, int]:
        """
        Validates file size, true magic bytes, and dimensions.
        Returns: (detected_format, width, height)
        """
        if not image_bytes:
            raise ImageProcessingError("Uploaded file is empty (0 bytes).")

        if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
            raise ImageProcessingError(
                f"Image file size ({len(image_bytes)} bytes) exceeds the maximum allowed limit of {MAX_IMAGE_SIZE_BYTES} bytes (10MB)."
            )

        # Magic byte validation (do not trust client MIME headers)
        fmt = None
        if image_bytes.startswith(PNG_MAGIC):
            fmt = "PNG"
        elif image_bytes.startswith(JPEG_MAGIC):
            fmt = "JPEG"
        elif image_bytes.startswith(WEBP_MAGIC_RIFF) and len(image_bytes) >= 12 and image_bytes[8:12] == WEBP_MAGIC_WEBP:
            fmt = "WEBP"
        else:
            raise ImageProcessingError(
                "Unsupported file format. Only genuine PNG, JPEG, and WebP images are permitted."
            )

        # Verify integrity and decode dimensions using PIL
        try:
            buf = io.BytesIO(image_bytes)
            with Image.open(buf) as img:
                img.verify()
                
            # Re-read image dimensions after verification
            buf.seek(0)
            with Image.open(buf) as img:
                width, height = img.size

        except Exception as e:
            raise ImageProcessingError(f"Corrupted or unreadable image stream: {str(e)}") from e

        if width < MIN_DIMENSION or height < MIN_DIMENSION:
            raise ImageProcessingError(
                f"Image dimensions ({width}x{height}) are too small. Minimum required is {MIN_DIMENSION}x{MIN_DIMENSION} pixels."
            )

        if width > MAX_DIMENSION or height > MAX_DIMENSION:
            raise ImageProcessingError(
                f"Image dimensions ({width}x{height}) exceed maximum allowed of {MAX_DIMENSION}x{MAX_DIMENSION} pixels."
            )

        return fmt, width, height

    def preprocess_image(self, image_bytes: bytes) -> bytes:
        """
        Enhances image contrast, sharpens edges, and normalizes grayscale to maximize OCR character recognition.
        """
        try:
            buf = io.BytesIO(image_bytes)
            with Image.open(buf) as img:
                # Convert to grayscale
                gray = img.convert("L")
                
                # Scale up small/medium images to improve character legibility and punctuation detection
                w, h = gray.size
                if w < 1000 or h < 500:
                    scale = max(1000 / w, 500 / h)
                    gray = gray.resize((int(w * scale), int(h * scale)), Image.Resampling.LANCZOS)

                # Enhance contrast
                enhancer = ImageEnhance.Contrast(gray)
                enhanced = enhancer.enhance(1.8)

                # Sharpen text edge boundaries
                sharpener = ImageEnhance.Sharpness(enhanced)
                sharpened = sharpener.enhance(1.6)

                out_buf = io.BytesIO()
                sharpened.save(out_buf, format="PNG")
                return out_buf.getvalue()
        except Exception as e:
            logger.warning(f"Image preprocessing failed, falling back to raw bytes: {e}")
            return image_bytes

    def extract_text_from_bytes(self, image_bytes: bytes) -> tuple[str, dict]:
        """
        Validates, preprocesses, and extracts text with per-token confidence metrics.
        Returns: (cleaned_text, metadata_dict)
        """
        fmt, w, h = self.validate_image(image_bytes)
        
        preprocessed_bytes = self.preprocess_image(image_bytes)
        reader = self._get_reader()

        try:
            # detail=1 returns list of tuples: (bbox, text, confidence)
            raw_results = reader.readtext(preprocessed_bytes, detail=1)
            raw_lines = [r[1] for r in raw_results if r[1].strip()]
            confidences = [float(r[2]) for r in raw_results if r[1].strip()]

            raw_joined = "\n".join(raw_lines).strip()
            
            # Post-process common OCR punctuation distortions in URLs and codes
            cleaned = self._repair_ocr_artifacts(raw_joined)

            mean_conf = float(sum(confidences) / len(confidences)) if confidences else 1.0
            min_conf = float(min(confidences)) if confidences else 1.0
            has_uncertain = any(c < 0.65 for c in confidences)
            
            meta = {
                "format": fmt,
                "dimensions": f"{w}x{h}",
                "line_count": len(raw_lines),
                "raw_ocr_length": len(raw_joined),
                "mean_ocr_confidence": round(mean_conf, 3),
                "min_ocr_confidence": round(min_conf, 3),
                "has_uncertain_tokens": has_uncertain,
            }
            return cleaned, meta

        except Exception as e:
            raise ImageProcessingError(f"Error during OCR text extraction: {str(e)}") from e

    def _repair_ocr_artifacts(self, text: str) -> str:
        """
        Fixes common character confusions in URLs and phone numbers without corrupting text.
        e.g. 'http I' -> 'http://', 'http l' -> 'http://', 'httpl' -> 'http://'
        """
        # Fix corrupted protocol delimiters e.g. http :// or http l or httplsbi-kyc
        repaired = re.sub(
            r"\b(https?)\s*[:|I!l/\s]{1,4}(?=[a-zA-Z0-9.-]+\.[a-z]{2,})",
            r"\1://",
            text,
            flags=re.IGNORECASE
        )
        return repaired
