import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root if it exists
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
env_path = ROOT_DIR / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

class Settings:
    # Model Provider Settings
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3:latest")
    MODEL_REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("MODEL_REQUEST_TIMEOUT_SECONDS", "90.0"))

    # Server Settings
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # OCR Settings
    OCR_ENABLED: bool = os.getenv("OCR_ENABLED", "true").lower() in ("true", "1", "yes")
    OCR_LANGUAGES: list[str] = os.getenv("OCR_LANGUAGES", "en").split(",")

settings = Settings()
