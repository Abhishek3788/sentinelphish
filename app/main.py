from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.db.session import init_db
from app.api.routes import router as api_router
from app.api.middleware import LoggingAndHeaderMiddleware
from app.utils.logger import get_logger

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing SentinelPhish Application Gateway...")
    await init_db()
    yield
    logger.info("Shutting down SentinelPhish Gateway...")


app = FastAPI(
    title="SentinelPhish API Gateway",
    description="Advanced AI-Powered Multi-Layer Phishing URL Detection System",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS for Chrome Extension and Web Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom logging and timing middleware
app.add_middleware(LoggingAndHeaderMiddleware)

# Include API Router
app.include_router(api_router)


@app.get("/")
async def root():
    return {
        "service": "SentinelPhish API Gateway",
        "status": "online",
        "documentation": "/docs",
        "version": "1.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
