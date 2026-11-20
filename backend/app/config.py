"""Runtime configuration, read from environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


# Allow scanning private / loopback addresses (only enable for local lab use).
ALLOW_PRIVATE_TARGETS = _bool("VULNSIGHT_ALLOW_PRIVATE", False)
# SQLite database used for scan history.
DB_PATH = Path(os.getenv("VULNSIGHT_DB", BASE_DIR / "vulnsight.db"))
# Built frontend served by FastAPI in production.
FRONTEND_DIST = Path(os.getenv("VULNSIGHT_FRONTEND", BASE_DIR.parent / "frontend" / "dist"))
# Scans allowed per client IP per minute.
RATE_LIMIT_PER_MIN = int(os.getenv("VULNSIGHT_RATE_LIMIT", "6"))
# Comma separated CORS origins for local development.
CORS_ORIGINS = [o.strip() for o in os.getenv(
    "VULNSIGHT_CORS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]

HTTP_TIMEOUT = float(os.getenv("VULNSIGHT_HTTP_TIMEOUT", "8"))
USER_AGENT = "VulnSight/1.0 (+https://github.com/ALLaNRoY-TECH/VulnSight; security-assessment)"
