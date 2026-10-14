"""Environment-backed runtime configuration."""

from dataclasses import dataclass
import json
import logging
import os
import sys


@dataclass(frozen=True)
class Settings:
    otx_api_key: str | None = None
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    otx_timeout_seconds: float = 10.0
    max_indicator_length: int = 2048

    @classmethod
    def from_env(cls) -> "Settings":
        timeout_value = os.getenv("OTX_TIMEOUT_SECONDS", "10")
        try:
            timeout = float(timeout_value)
        except ValueError as exc:
            raise ValueError("OTX_TIMEOUT_SECONDS must be a positive number") from exc
        if timeout <= 0:
            raise ValueError("OTX_TIMEOUT_SECONDS must be a positive number")

        api_key = os.getenv("OTX_API_KEY", "").strip() or None
        base_url = os.getenv(
            "OTX_BASE_URL", "https://otx.alienvault.com/api/v1"
        ).rstrip("/")
        if not base_url.startswith("https://"):
            raise ValueError("OTX_BASE_URL must use HTTPS")

        return cls(otx_api_key=api_key, otx_base_url=base_url,
                   otx_timeout_seconds=timeout)


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {"event": record.getMessage()}
        for field in ("source", "status", "error_code", "duration_ms"):
            if hasattr(record, field):
                event[field] = getattr(record, field)
        return json.dumps(event, separators=(",", ":"))


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonLogFormatter())
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)
