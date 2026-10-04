import io
import pytest
from PIL import Image
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.services.image_extractor import ImageTextExtractor
from backend.app.core.errors import ImageProcessingError

def create_test_image(format="PNG", size=(200, 200), color=(255, 255, 255)) -> bytes:
    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format=format)
    return buf.getvalue()

def test_image_validation_valid_formats():
    extractor = ImageTextExtractor()
    
    png_bytes = create_test_image("PNG")
    fmt, w, h = extractor.validate_image(png_bytes)
    assert fmt == "PNG"
    assert w == 200 and h == 200

    jpeg_bytes = create_test_image("JPEG")
    fmt, w, h = extractor.validate_image(jpeg_bytes)
    assert fmt == "JPEG"

    webp_bytes = create_test_image("WEBP")
    fmt, w, h = extractor.validate_image(webp_bytes)
    assert fmt == "WEBP"

def test_image_validation_too_small():
    extractor = ImageTextExtractor()
    small_bytes = create_test_image("PNG", size=(30, 30))
    with pytest.raises(ImageProcessingError) as exc:
        extractor.validate_image(small_bytes)
    assert "too small" in str(exc.value)

def test_image_validation_empty_bytes():
    extractor = ImageTextExtractor()
    with pytest.raises(ImageProcessingError) as exc:
        extractor.validate_image(b"")
    assert "empty" in str(exc.value)

def test_image_validation_fake_magic_bytes():
    extractor = ImageTextExtractor()
    fake_bytes = b"NOT_AN_IMAGE_AT_ALL_JUST_TEXT"
    with pytest.raises(ImageProcessingError) as exc:
        extractor.validate_image(fake_bytes)
    assert "Unsupported file format" in str(exc.value)

def test_image_validation_oversized_bytes():
    extractor = ImageTextExtractor()
    oversized = b"\x89PNG\r\n\x1a\n" + (b"\x00" * (11 * 1024 * 1024))
    with pytest.raises(ImageProcessingError) as exc:
        extractor.validate_image(oversized)
    assert "exceeds the maximum allowed limit" in str(exc.value)

@pytest.mark.asyncio
async def test_image_analysis_endpoint_invalid_file():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("test.txt", b"plain text content", "text/plain")}
        res = await client.post("/api/analyze/image", files=files)
        assert res.status_code == 422
        assert "Unsupported file format" in res.json()["detail"]

@pytest.mark.asyncio
async def test_image_analysis_endpoint_corrupted_image():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # PNG magic header with corrupt body
        corrupt_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRcorrupted"
        files = {"file": ("corrupt.png", corrupt_png, "image/png")}
        res = await client.post("/api/analyze/image", files=files)
        assert res.status_code == 422
