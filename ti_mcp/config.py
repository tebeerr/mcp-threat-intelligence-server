"""Environment-backed runtime configuration."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys

from dotenv import load_dotenv

_REPO_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
_DEFAULT_DATA_DIR = Path.home() / ".ti-mcp"


def load_env_file() -> None:
    """Load `.env` without overriding the process environment.

    MCP clients such as Claude Desktop start the server from an arbitrary
    working directory, so the checkout's own `.env` is tried after the cwd.
    """
    explicit = os.getenv("TI_MCP_ENV_FILE")
    for candidate in ([Path(explicit)] if explicit else [Path.cwd() / ".env", _REPO_ENV_FILE]):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return


def _positive_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


def _non_negative_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a non-negative integer") from exc
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _https_url(name: str, default: str | None = None) -> str | None:
    value = (os.getenv(name, "").strip() or default or "").rstrip("/")
    if not value:
        return None
    if not value.startswith("https://"):
        raise ValueError(f"{name} must use HTTPS")
    return value


def _secret(name: str) -> str | None:
    return os.getenv(name, "").strip() or None


@dataclass(frozen=True)
class Settings:
    otx_api_key: str | None = field(default=None, repr=False)
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    otx_timeout_seconds: float = 10.0
    urlhaus_auth_key: str | None = field(default=None, repr=False)
    urlhaus_base_url: str = "https://urlhaus-api.abuse.ch/v1"
    urlhaus_timeout_seconds: float = 10.0
    source_timeout_seconds: float = 15.0
    max_indicator_length: int = 2048
    max_alert_indicators: int = 10
    cache_path: Path = _DEFAULT_DATA_DIR / "cache.sqlite3"
    cache_ttl_seconds: int = 3600
    attack_stix_path: Path = _DEFAULT_DATA_DIR / "enterprise-attack.json"
    wazuh_indexer_url: str | None = None
    wazuh_username: str | None = None
    wazuh_password: str | None = field(default=None, repr=False)
    wazuh_ca_bundle: str | None = None
    wazuh_alert_index: str = "wazuh-alerts-*"
    wazuh_timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.getenv("TI_MCP_DATA_DIR", "").strip() or _DEFAULT_DATA_DIR)
        return cls(
            otx_api_key=_secret("OTX_API_KEY"),
            otx_base_url=_https_url("OTX_BASE_URL", cls.otx_base_url),
            otx_timeout_seconds=_positive_float("OTX_TIMEOUT_SECONDS", cls.otx_timeout_seconds),
            urlhaus_auth_key=_secret("URLHAUS_AUTH_KEY"),
            urlhaus_base_url=_https_url("URLHAUS_BASE_URL", cls.urlhaus_base_url),
            urlhaus_timeout_seconds=_positive_float(
                "URLHAUS_TIMEOUT_SECONDS", cls.urlhaus_timeout_seconds
            ),
            source_timeout_seconds=_positive_float(
                "SOURCE_TIMEOUT_SECONDS", cls.source_timeout_seconds
            ),
            max_alert_indicators=_non_negative_int(
                "MAX_ALERT_INDICATORS", cls.max_alert_indicators
            ),
            cache_path=Path(os.getenv("CACHE_DB_PATH", "").strip() or data_dir / "cache.sqlite3"),
            cache_ttl_seconds=_non_negative_int("CACHE_TTL_SECONDS", cls.cache_ttl_seconds),
            attack_stix_path=Path(
                os.getenv("ATTACK_STIX_PATH", "").strip() or data_dir / "enterprise-attack.json"
            ),
            wazuh_indexer_url=_https_url("WAZUH_INDEXER_URL"),
            wazuh_username=_secret("WAZUH_USERNAME"),
            wazuh_password=_secret("WAZUH_PASSWORD"),
            wazuh_ca_bundle=os.getenv("WAZUH_CA_BUNDLE", "").strip() or None,
            wazuh_alert_index=os.getenv("WAZUH_ALERT_INDEX", "").strip() or cls.wazuh_alert_index,
            wazuh_timeout_seconds=_positive_float(
                "WAZUH_TIMEOUT_SECONDS", cls.wazuh_timeout_seconds
            ),
        )


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        for name in ("source", "status", "error_code", "from_cache", "duration_ms", "error_type"):
            if hasattr(record, name):
                event[name] = getattr(record, name)
        return json.dumps(event, separators=(",", ":"))


def configure_logging() -> None:
    # stdout carries the MCP stream: logs must only ever go to stderr.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonLogFormatter())
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)
    # httpx logs full request URLs at INFO, which would duplicate IOCs in logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
