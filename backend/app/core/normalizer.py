import unicodedata
import re

# Regex for common zero-width and invisible control characters used in evasion
INVISIBLE_CHARS_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u00A0\u200E\u200F\u202A-\u202E]")

def normalize_text(raw_text: str) -> str:
    """
    Normalizes input text for analysis:
    1. Normalizes Unicode representations (NFKC).
    2. Strips out invisible/zero-width evasion characters.
    3. Normalizes whitespace, carriage returns, and excessive newlines.
    4. Strips leading and trailing space.
    """
    if not raw_text:
        return ""

    # Unicode normalization converts compatibility characters to canonical equivalents
    normalized = unicodedata.normalize("NFKC", raw_text)

    # Strip zero-width evasion artifacts
    normalized = INVISIBLE_CHARS_REGEX.sub(" ", normalized)

    # Standardize carriage returns
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")

    # Collapse excessive consecutive newlines (max 2)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)

    # Collapse multiple consecutive horizontal spaces to a single space
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in normalized.split("\n")]
    
    return "\n".join(lines).strip()
