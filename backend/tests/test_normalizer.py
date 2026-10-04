from backend.app.core.normalizer import normalize_text

def test_normalize_empty_text():
    assert normalize_text("") == ""
    assert normalize_text("   \n\n\t  ") == ""

def test_normalize_strips_zero_width_and_invisible_chars():
    # \u200b is zero-width space often injected into 'o t p' or phishing URLs
    dirty = "Please\u200b enter your\u200c password\uFEFF now"
    cleaned = normalize_text(dirty)
    assert "\u200b" not in cleaned
    assert "\u200c" not in cleaned
    assert "\uFEFF" not in cleaned
    assert "Please enter your password now" == cleaned

def test_normalize_collapses_excessive_newlines():
    text = "Line 1\n\n\n\n\n\nLine 2"
    cleaned = normalize_text(text)
    assert cleaned == "Line 1\n\nLine 2"

def test_normalize_unicode_compatibility():
    # Fullwidth latin characters like ＨＤＦＣ should normalize to HDFC
    fullwidth = "Your \uff28\uff24\uff26\uff23 bank account"
    cleaned = normalize_text(fullwidth)
    assert "HDFC" in cleaned
