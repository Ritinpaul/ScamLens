import io
import pytest
from PIL import Image, ImageDraw
from backend.app.services.image_extractor import ImageTextExtractor
from backend.app.services.url_extractor import UrlExtractor
from backend.app.models.verifier_schema import UrlCertainty
from backend.app.services.deterministic_verifier import DeterministicVerifier

def create_synthetic_test_image(text: str) -> bytes:
    img = Image.new("RGB", (700, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 40), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def test_ocr_preprocessing_enhancement():
    extractor = ImageTextExtractor()
    raw_img = create_synthetic_test_image("Test Alert: Urgent KYC")
    preprocessed = extractor.preprocess_image(raw_img)
    
    assert len(preprocessed) > 0
    # Verify preprocessed output is valid image
    with Image.open(io.BytesIO(preprocessed)) as img:
        assert img.mode == "L"  # Grayscale
        assert img.size[0] >= 1000  # Upscaled to >= 1000px

def test_ocr_confidence_tracking_and_metadata():
    extractor = ImageTextExtractor()
    raw_img = create_synthetic_test_image("State Bank Alert: http://example.com")
    text, meta = extractor.extract_text_from_bytes(raw_img)
    
    assert isinstance(text, str)
    assert "mean_ocr_confidence" in meta
    assert "min_ocr_confidence" in meta
    assert "has_uncertain_tokens" in meta
    assert 0.0 <= meta["mean_ocr_confidence"] <= 1.0

def test_url_extractor_confident_url():
    extractor = UrlExtractor()
    text = "Please log in to your account at https://secure-bank.example.com/login now."
    urls = extractor.extract_urls(text)
    
    assert len(urls) >= 1
    confident = urls[0]
    assert confident.certainty == UrlCertainty.CONFIDENT
    assert confident.scheme == "https"
    assert confident.host == "secure-bank.example.com"
    assert confident.path == "/login"
    assert confident.reconstructed_candidate is None

def test_url_extractor_probable_url():
    extractor = UrlExtractor()
    text = "Visit bit.ly/my-alert-link immediately"
    urls = extractor.extract_urls(text)
    
    assert len(urls) >= 1
    assert urls[0].is_shortener is True
    assert urls[0].certainty in (UrlCertainty.CONFIDENT, UrlCertainty.PROBABLE)

def test_url_extractor_ocr_malformed_url_uncertainty():
    extractor = UrlExtractor()
    # Simulates common OCR artifact: space before TLD or broken protocol delimiter
    ocr_corrupted_text = "Update your KYC immediately http lisbi-kyc xyz verify"
    urls = extractor.extract_urls(ocr_corrupted_text)
    
    assert len(urls) >= 1
    uncertain = [u for u in urls if u.certainty == UrlCertainty.UNCERTAIN]
    assert len(uncertain) >= 1
    u = uncertain[0]
    # Raw OCR snippet is preserved intact
    assert "http" in u.raw_url
    assert u.certainty == UrlCertainty.UNCERTAIN
    assert u.reconstructed_candidate is not None
    # Reconstructed candidate handles the broken delimiter without guessing characters
    assert "http://" in u.reconstructed_candidate
    assert "sbi-kyc.xyz" in u.reconstructed_candidate
    assert any("OCR noise detected" in note for note in u.notes)

def test_deterministic_verifier_flags_uncertain_urls():
    verifier = DeterministicVerifier()
    text = "Update your account details at http lisbi-kyc xyz verify immediately"
    res = verifier.verify(text)
    
    assert res.has_uncertain_urls is True
    uncertain_signals = [s for s in res.signals if s.pattern_matched == "malformed_ocr_url_candidate"]
    assert len(uncertain_signals) >= 1
    assert uncertain_signals[0].severity.value == "high"

def test_raw_ocr_preserved_never_silently_invented():
    extractor = UrlExtractor()
    # If text has ambiguous letters like examp1e vs example, raw text must stay examp1e
    text = "Login to http://examp1e.com/verify"
    urls = extractor.extract_urls(text)
    
    assert len(urls) >= 1
    assert urls[0].host == "examp1e.com"
    # Does NOT silently alter 'examp1e' to 'example'
    assert "example.com" not in urls[0].raw_url
