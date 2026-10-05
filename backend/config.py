"""Centralized configuration for ARPShield backend.

Defines database locations, packet logging limits, CORS, and runtime settings.
"""

import os
from pathlib import Path

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
INSTANCE_DIR = BACKEND_DIR / "instance"

# Ensure instance directory exists for SQLite
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_DB_PATH = INSTANCE_DIR / "arpshield.db"


class Config:
    """Application configuration."""

    # Secret key for sessions/tokens
    SECRET_KEY = os.environ.get("SECRET_KEY", "arpshield-rule-based-dev-secret")

    # SQLite Database URI (uses absolute path for consistency)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Packet Log Retention & Sampling (Capstone-scale SQLite safeguards)
    MAX_ARP_PACKET_LOGS = int(os.environ.get("MAX_ARP_PACKET_LOGS", 5000))
    PACKET_SAMPLE_RATE = int(os.environ.get("PACKET_SAMPLE_RATE", 5))

    # CORS Configuration
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
