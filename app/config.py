from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    GROQ_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None

    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinelphish.db"
    SUPABASE_URL: Optional[str] = None
    SUPABASE_KEY: Optional[str] = None

    REDIS_URL: str = "redis://localhost:6379/0"
    UPSTASH_REDIS_URL: Optional[str] = None
    UPSTASH_REDIS_TOKEN: Optional[str] = None

    SECRET_KEY: str = "sentinelphish_secret_dev_key_2026"
    API_RATE_LIMIT_PER_DAY: int = 1000
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: str = "development"

    # Layer Timeouts (in seconds)
    LEXICAL_TIMEOUT: float = 1.0
    DOMAIN_INTEL_TIMEOUT: float = 5.0
    CONTENT_TIMEOUT: float = 10.0
    THREAT_INTEL_TIMEOUT: float = 6.0
    VISUAL_TIMEOUT: float = 12.0
    AI_TIMEOUT: float = 8.0
    ML_TIMEOUT: float = 2.0
    BEHAVIORAL_TIMEOUT: float = 8.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
