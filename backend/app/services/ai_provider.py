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
  "requests": ["<specific dangerous or suspicious action requested of recipient e.g. click link, install APK, send money, disclose OTP>"],
  "entities": ["<organizations, banks, or brands claimed>"],
  "urls": ["<urls or domains detected>"],
  "recommended_action": "<clear actionable instruction for non-technical user>",
  "uncertainty_reason": "<honest statement of what is ambiguous or unverified>",
  "confidence_label": "model_unvalidated",
  "requests_secret_disclosure": false,
  "requests_payment": false,
  "requests_external_action": false,
  "contains_negative_security_warning": false,
  "contains_transaction_notification": false,
  "contains_normal_due_date_language": false,
  "impersonates_authority": false,
  "uses_coercive_urgency": false
}

CRITICAL RULES FOR CONTEXTUAL CALIBRATION:
1. Negative Security Warnings vs Credential Theft:
   - "DO NOT share this OTP with anyone", "Never disclose your password", or "forward to 9223008333 if not done by you" are PROTECTIVE SECURITY NOTICES.
   - When a message warns the user NOT to share their code, set "contains_negative_security_warning": true, "requests_secret_disclosure": false, and do NOT list "do not share" under requests.
   - If a message simply delivers an OTP for login with a "do not share" warning and no suspicious link, its verdict is "likely_legitimate".
   - Only set "requests_secret_disclosure": true and verdict "scam" if the sender ASKS or DEMANDS the recipient to share, send, or disclose an OTP, password, PIN, or CVV.

2. Transactional & Due Date Notifications vs Coercive Urgency:
   - Standard transactional debit/credit notifications (e.g. "Your account XX1234 debited INR 500. Avail balance... If not done by you...") are normal bank communications. Set "contains_transaction_notification": true, "uses_coercive_urgency": false, and verdict "likely_legitimate".
   - Routine billing reminders (e.g. "Bill is Rs 1,240. Due date is Oct 15. Avoid late fee by paying on time via official app") use normal commercial timelines. Set "contains_normal_due_date_language": true, "uses_coercive_urgency": false, and verdict "likely_legitimate".
   - Standard promotional notices (e.g. "Sale ends Sunday 8 PM. Show at billing counter") are benign commerce. Verdict: "likely_legitimate".
   - Only set "uses_coercive_urgency": true if there is an extreme, imminent threat intended to panic the victim into immediate compliance (e.g. "disconnected TONIGHT at 9:30 PM", "arrest warrant issued", "terminated in 24 hours").

3. Official App / Portal Guidance vs Malicious Links:
   - Advising users to use official trusted channels ("track in Amazon app", "visit Google Account Security Dashboard", "pay via official board app") without suspicious external links is standard legitimate practice.
   - Genuine security alerts informing of a login or password change that recommend checking the official dashboard are "likely_legitimate".

4. Verdict Definitions:
   - "scam": Clear evidence of deception, credential harvesting, extortion, advance-fee fraud, reverse QR code scam, or impersonation pushing a dangerous action.
   - "suspicious": Unverified claims, unknown shortened links, or unsolicited outreach that warrants caution but lacks definitive proof.
   - "likely_legitimate": Routine transactional alerts, negative security warnings, normal due-date reminders, standard job confirmations, or friendly non-coercive chats.
   - "insufficient_evidence": Too short, garbled, or completely ambiguous text.

5. Accuracy & Honesty:
   - NEVER fabricate tactics. If a message is a normal billing reminder, DO NOT label "avoid late fee" as artificial_urgency.
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
            # Defensively normalize list-of-string fields (e.g. requests, entities, urls)
            # if model returns [{'action': '...'}, ...] instead of ['...']
            if isinstance(parsed, dict):
                for key in ("requests", "entities", "urls"):
                    if key in parsed and isinstance(parsed[key], list):
                        norm_list = []
                        for item in parsed[key]:
                            if isinstance(item, str):
                                norm_list.append(item)
                            elif isinstance(item, dict):
                                val = next((str(v) for v in item.values() if isinstance(v, (str, int))), str(item))
                                norm_list.append(val)
                            else:
                                norm_list.append(str(item))
                        parsed[key] = norm_list

                # Defensively normalize boolean fields if model returned strings like "true"/"false"
                for bool_key in (
                    "requests_secret_disclosure",
                    "requests_payment",
                    "requests_external_action",
                    "contains_negative_security_warning",
                    "contains_transaction_notification",
                    "contains_normal_due_date_language",
                    "impersonates_authority",
                    "uses_coercive_urgency",
                ):
                    if bool_key in parsed:
                        val = parsed[bool_key]
                        if isinstance(val, str):
                            parsed[bool_key] = val.strip().lower() in ("true", "yes", "1")
                        elif isinstance(val, (int, float)):
                            parsed[bool_key] = bool(val)

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
