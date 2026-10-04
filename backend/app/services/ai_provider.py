import abc
import json
import logging
import re
import httpx
from pydantic import ValidationError
from backend.app.config import settings
from backend.app.core.errors import ModelConnectionError, ModelInferenceError, SchemaValidationError
from backend.app.models.ai_schema import AiAnalysisOutput

logger = logging.getLogger(__name__)

SCAM_ANALYSIS_SYSTEM_PROMPT = """You are an expert security analyst specialized in identifying scam messages, phishing campaigns, impersonation fraud, and social engineering manipulation across SMS, WhatsApp, email, and social networks.

Analyze the user's message and determine its intent, psychological tactics, and potential risk.
You MUST output valid, raw JSON conforming EXACTLY to this structure with no markdown formatting around it:
{
  "verdict": "scam" | "suspicious" | "likely_legitimate" | "insufficient_evidence",
  "summary": "<plain English summary of message intent>",
  "tactics": [
    {
      "type": "<tactic e.g. artificial_urgency, fear_threat, authority_impersonation, lottery_bait, investment_fraud>",
      "evidence": "<specific quote or reasoning from the message>"
    }
  ],
  "requests": ["<action requested of recipient e.g. click link, install APK, send money>"],
  "entities": ["<organizations, banks, or brands claimed>"],
  "urls": ["<urls or domains detected>"],
  "recommended_action": "<clear actionable instruction for non-technical user>",
  "uncertainty_reason": "<honest statement of what is ambiguous or unverified>",
  "confidence_label": "model_unvalidated"
}

Guidelines:
- "scam": Clear evidence of fraud, credential harvesting, threats, or impersonation.
- "suspicious": Contains red flags or unverified urgent claims, but lacks conclusive proof.
- "likely_legitimate": Standard conversational text or genuine routine notification with no manipulative elements.
- "insufficient_evidence": Too short, garbled, or ambiguous to determine.
- NEVER fabricate tactics not supported by the message text.
- Be honest in "uncertainty_reason".
"""

class ModelProvider(abc.ABC):
    """Abstract interface for local open-source inference runtimes."""

    @abc.abstractmethod
    async def is_available(self) -> tuple[bool, str]:
        """Check if the model runtime is active and accessible."""
        pass

    @abc.abstractmethod
    async def analyze_text(self, text: str) -> AiAnalysisOutput:
        """Analyze text and return structured JSON conforming to AiAnalysisOutput."""
        pass

class OllamaProvider(ModelProvider):
    """Real Ollama local model provider using the Ollama HTTP API."""

    def __init__(self, base_url: str | None = None, model: str | None = None, timeout: float | None = None):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL
        self.timeout = timeout or settings.MODEL_REQUEST_TIMEOUT_SECONDS

    async def is_available(self) -> tuple[bool, str]:
        """Verify that Ollama is responding and the target model is loaded or accessible."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    # Check if requested model or matching prefix exists
                    model_found = any(self.model in m or m in self.model for m in models)
                    if model_found:
                        return True, f"Ollama online, model '{self.model}' available"
                    return False, f"Ollama online, but model '{self.model}' not found. Available models: {models}"
                return False, f"Ollama responded with status code {response.status_code}"
        except httpx.ConnectError:
            return False, f"Cannot connect to Ollama at {self.base_url}. Ensure 'ollama serve' is running."
        except Exception as e:
            return False, f"Ollama check failed: {str(e)}"

    async def analyze_text(self, text: str) -> AiAnalysisOutput:
        """Call local Ollama instance with JSON format enforcement."""
        if not text or not text.strip():
            raise ModelInferenceError("Cannot analyze empty message text.")

        payload = {
            "model": self.model,
            "prompt": f"Message to analyze:\n```\n{text}\n```",
            "system": SCAM_ANALYSIS_SYSTEM_PROMPT,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for deterministic adherence to schema
            }
        }

        url = f"{self.base_url}/api/generate"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)
        except httpx.ConnectError as e:
            raise ModelConnectionError(
                f"Could not connect to Ollama at {self.base_url}. Ensure the Ollama server is running locally.",
                details={"base_url": self.base_url, "error": str(e)}
            ) from e
        except httpx.TimeoutException as e:
            raise ModelInferenceError(
                f"Ollama inference timed out after {self.timeout} seconds for model '{self.model}'.",
                details={"model": self.model, "timeout": self.timeout}
            ) from e
        except Exception as e:
            raise ModelInferenceError(f"Unexpected error communicating with Ollama: {str(e)}") from e

        if response.status_code != 200:
            raise ModelInferenceError(
                f"Ollama returned HTTP {response.status_code}: {response.text}",
                details={"status_code": response.status_code, "response": response.text}
            )

        try:
            res_json = response.json()
            raw_output = res_json.get("response", "")
        except Exception as e:
            raise ModelInferenceError(f"Failed to parse Ollama response envelope as JSON: {str(e)}") from e

        # Extract and parse JSON
        cleaned_json = self._extract_json_string(raw_output)

        try:
            parsed = json.loads(cleaned_json)
        except json.JSONDecodeError as e:
            raise SchemaValidationError(
                f"Model response was not valid JSON: {str(e)}",
                details={"raw_output": raw_output}
            ) from e

        try:
            validated = AiAnalysisOutput.model_validate(parsed)
            return validated
        except ValidationError as e:
            raise SchemaValidationError(
                f"Model output failed schema validation: {str(e)}",
                details={"errors": e.errors(), "parsed": parsed}
            ) from e

    def _extract_json_string(self, text: str) -> str:
        """Strip markdown fences if the model wrapped the JSON in code blocks."""
        text = text.strip()
        if text.startswith("```"):
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
            if match:
                return match.group(1).strip()
        return text
