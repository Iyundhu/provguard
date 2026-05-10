"""
Configuration for ProvGuard.
Loads environment variables for API keys, database paths, and app settings.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings:
    APP_NAME: str = "ProvGuard"
    APP_TAGLINE: str = "Trust by Verification, Not Detection"
    VERSION: str = "1.0.0"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR.parent / 'data' / 'provguard.db'}"
    )

    # File storage
    UPLOAD_DIR: Path = BASE_DIR.parent / "data" / "uploads"
    KEYS_DIR: Path = BASE_DIR.parent / "data" / "keys"
    MAX_UPLOAD_SIZE: int = 25 * 1024 * 1024  # 25 MB

    # VirusTotal
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_URL: str = "https://www.virustotal.com/api/v3/files"

    # Risk scoring weights (must sum to 1.0)
    WEIGHT_THREAT_INTEL: float = 0.50
    WEIGHT_PROVENANCE: float = 0.30
    WEIGHT_BEHAVIORAL: float = 0.20

    # Decision thresholds (lower score = higher risk)
    TRUSTED_THRESHOLD: int = 70
    SUSPICIOUS_THRESHOLD: int = 40

    def __init__(self):
        self.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        self.KEYS_DIR.mkdir(parents=True, exist_ok=True)

settings = Settings()
