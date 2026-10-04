import io
import pytest
from PIL import Image, ImageDraw
from httpx import AsyncClient, ASGITransport
from backend.app.main import app

@pytest.mark.asyncio
async def test_image_analysis_endpoint_invalid_file():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Send a non-image file
        files = {"file": ("test.txt", b"plain text content", "text/plain")}
        res = await client.post("/api/analyze/image", files=files)
        assert res.status_code == 400
        assert "Uploaded file must be an image" in res.json()["detail"]

@pytest.mark.asyncio
async def test_image_analysis_endpoint_corrupted_image():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("corrupt.png", b"not an image at all", "image/png")}
        res = await client.post("/api/analyze/image", files=files)
        assert res.status_code == 422
