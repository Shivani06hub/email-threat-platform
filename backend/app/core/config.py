"""
Central configuration for the app.
Values are read from environment variables (.env file) so that
secrets never get hardcoded into the codebase.
"""

import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    APP_NAME: str = "Email Threat Intelligence Platform"
    ENV: str = os.getenv("ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "True") == "True"

    ALLOWED_ORIGINS: list = os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:5173"
    ).split(",")

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./app.db")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60 * 8  # 8 hours


settings = Settings()