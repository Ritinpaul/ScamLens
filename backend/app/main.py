import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import settings
from backend.app.api.routes import router

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("scamlens")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing ScamLens backend...")
    logger.info(f"Target Ollama model: {settings.OLLAMA_MODEL} at {settings.OLLAMA_BASE_URL}")
    yield
    logger.info("Shutting down ScamLens backend.")

app = FastAPI(
    title="ScamLens API",
    description="Privacy-First Local Scam & Social Engineering Analyzer",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
