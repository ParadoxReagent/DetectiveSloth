"""Application configuration using Pydantic settings."""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    DATABASE_URL: str = "sqlite:///./threat_hunt.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = True
    SECRET_KEY: str = "dev-secret-key-change-in-production"

    # Threat Intelligence API Keys
    OTX_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

    # Update Intervals (hours)
    MITRE_UPDATE_INTERVAL: int = 24
    THREAT_INTEL_UPDATE_INTERVAL: int = 6

    # Query Settings
    DEFAULT_TIMEFRAME: str = "7d"
    MAX_QUERY_RESULTS: int = 1000

    # MITRE ATT&CK URLs
    MITRE_STIX_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


# Global settings instance
settings = Settings()
