import pytest
from pydantic import ValidationError
from backend.app.models.ai_schema import AiAnalysisOutput, AiVerdict, TacticItem
from backend.app.services.ai_provider import OllamaProvider

def test_ai_schema_valid():
    data = {
        "verdict": "scam",
        "summary": "Message claims electricity will be disconnected tonight.",
        "tactics": [
            {"type": "artificial_urgency", "evidence": "tonight at 9:30 PM"},
            {"type": "authority_impersonation", "evidence": "Electricity Officer"}
        ],
        "requests": ["Call given officer number"],
        "entities": ["Electricity Department"],
        "urls": [],
        "recommended_action": "Do not call the number. Contact the electricity board directly.",
        "uncertainty_reason": "No formal bill number provided in text.",
        "confidence_label": "model_unvalidated"
    }
    model = AiAnalysisOutput.model_validate(data)
    assert model.verdict == AiVerdict.SCAM
    assert len(model.tactics) == 2
    assert model.tactics[0].type == "artificial_urgency"

def test_ai_schema_invalid_verdict():
    data = {
        "verdict": "definitely_not_a_scam_bro",  # Invalid enum value
        "summary": "Some summary",
        "recommended_action": "Do nothing"
    }
    with pytest.raises(ValidationError):
        AiAnalysisOutput.model_validate(data)

def test_ai_schema_missing_required_fields():
    data = {
        "verdict": "scam"
        # Missing summary, recommended_action
    }
    with pytest.raises(ValidationError):
        AiAnalysisOutput.model_validate(data)

def test_extract_json_from_markdown_blocks():
    provider = OllamaProvider()
    raw = '```json\n{"verdict": "suspicious", "summary": "test", "recommended_action": "test"}\n```'
    extracted = provider._extract_json_string(raw)
    assert extracted == '{"verdict": "suspicious", "summary": "test", "recommended_action": "test"}'

def test_extract_json_plain():
    provider = OllamaProvider()
    raw = '{"verdict": "scam", "summary": "test", "recommended_action": "test"}'
    assert provider._extract_json_string(raw) == raw
