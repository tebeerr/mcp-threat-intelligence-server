"""Shared asynchronous connector contract."""

from typing import Protocol

from ti_mcp.domain.models import Indicator, SourceResult


class ThreatIntelConnector(Protocol):
    name: str

    async def lookup(self, indicator: Indicator) -> SourceResult: ...
