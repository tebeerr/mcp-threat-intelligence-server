"""Shared connector contracts and helpers."""

from datetime import datetime, timezone
from typing import Any, Protocol

from ti_mcp.domain.models import AttackTechnique, ErrorCode, Indicator, SourceResult, SourceStatus


class ThreatIntelConnector(Protocol):
    name: str

    async def lookup(self, indicator: Indicator) -> SourceResult: ...


class AlertSource(Protocol):
    async def list_alerts(
        self, limit: int, min_level: int, since_hours: int
    ) -> list[dict[str, Any]]: ...

    async def get_alert(self, alert_id: str) -> dict[str, Any]: ...


class TechniqueCatalog(Protocol):
    async def get(self, technique_id: str) -> AttackTechnique | None: ...


def parse_timestamp(value: object) -> datetime | None:
    """Parse provider timestamps; providers omit the zone but report UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().removesuffix(" UTC").replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def error_result(name: str, retrieved_at: datetime, code: ErrorCode) -> SourceResult:
    return SourceResult(
        name=name,
        status=SourceStatus.ERROR,
        retrieved_at=retrieved_at,
        error_code=code,
    )
