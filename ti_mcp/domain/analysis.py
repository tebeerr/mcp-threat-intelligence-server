"""Protocol-independent analysis orchestration."""

import asyncio
import logging
from datetime import datetime, timezone
from time import perf_counter

from ti_mcp.connectors.base import ThreatIntelConnector
from ti_mcp.domain.correlation import correlate
from ti_mcp.domain.models import (
    ErrorCode,
    Indicator,
    LookupResult,
    Report,
    SourceResult,
    SourceStatus,
)
from ti_mcp.domain.risk import assess_risk
from ti_mcp.domain.validation import IndicatorValidationError, validate_indicator

logger = logging.getLogger(__name__)

_LIMITS = ["Passive threat-intelligence lookup only", "No direct contact with the indicator"]


class AnalysisService:
    def __init__(
        self,
        connectors: list[ThreatIntelConnector],
        max_indicator_length: int = 2048,
        source_timeout_seconds: float = 15.0,
    ):
        self._connectors = connectors
        self._max_indicator_length = max_indicator_length
        self._source_timeout_seconds = source_timeout_seconds

    async def analyze(self, value: str) -> Report:
        indicator = validate_indicator(value, self._max_indicator_length)
        results = await self._collect(indicator, self._connectors)
        unique_results, correlation = correlate(results)
        risk, uncertainty = assess_risk(unique_results, correlation)
        status = "partial" if any(result.status == SourceStatus.ERROR for result in unique_results) else "ok"
        return Report(
            status=status,
            indicator=indicator,
            sources=unique_results,
            correlation=correlation,
            risk=risk,
            uncertainty=uncertainty,
            summary=self._summary(indicator, unique_results, risk.level.value, uncertainty.level),
            limits=_LIMITS,
        )

    async def lookup(self, value: str, sources: list[str] | None = None) -> LookupResult:
        """Raw per-source facts, optionally restricted to named sources."""
        indicator = validate_indicator(value, self._max_indicator_length)
        connectors = self._connectors
        if sources:
            known = {connector.name for connector in connectors}
            if not set(sources) <= known:
                raise IndicatorValidationError(
                    "INVALID_INPUT", f"Unknown source; available: {', '.join(sorted(known))}"
                )
            connectors = [connector for connector in connectors if connector.name in sources]
        results = await self._collect(indicator, connectors)
        failed = any(result.status == SourceStatus.ERROR for result in results)
        return LookupResult(
            status="partial" if failed else "ok",
            indicator=indicator,
            sources=results,
            limits=_LIMITS,
        )

    async def _collect(
        self, indicator: Indicator, connectors: list[ThreatIntelConnector]
    ) -> list[SourceResult]:
        return list(
            await asyncio.gather(*(self._lookup(connector, indicator) for connector in connectors))
        )

    async def _lookup(self, connector: ThreatIntelConnector, indicator: Indicator) -> SourceResult:
        started = perf_counter()
        error_type = None
        try:
            # Hard bound over the whole lookup: httpx timeouts are per network operation.
            result = await asyncio.wait_for(
                connector.lookup(indicator), self._source_timeout_seconds
            )
        except TimeoutError:
            result = self._failure(connector, ErrorCode.SOURCE_TIMEOUT)
        except Exception as exc:
            error_type = type(exc).__name__
            result = self._failure(connector, ErrorCode.SOURCE_UNAVAILABLE)
        logger.info(
            "source_lookup_complete",
            extra={
                "source": connector.name,
                "status": result.status.value,
                "error_code": result.error_code.value if result.error_code else None,
                "error_type": error_type,
                "from_cache": result.from_cache,
                "duration_ms": round((perf_counter() - started) * 1000, 2),
            },
        )
        return result

    @staticmethod
    def _failure(connector: ThreatIntelConnector, code: ErrorCode) -> SourceResult:
        return SourceResult(
            name=connector.name,
            status=SourceStatus.ERROR,
            retrieved_at=datetime.now(timezone.utc),
            error_code=code,
        )

    @staticmethod
    def _summary(indicator: Indicator, results: list[SourceResult], risk: str, uncertainty: str) -> str:
        tags = sorted({tag for result in results for tag in result.tags})
        tag_text = f" Tags: {', '.join(tags)}." if tags else " No source tags returned."
        failed = sum(result.status == SourceStatus.ERROR for result in results)
        source_text = f" {failed} source(s) unavailable." if failed else " All queried sources responded."
        return (
            f"{indicator.type.value} analyzed with {len(results)} source(s).{tag_text}"
            f" Risk: {risk}; uncertainty: {uncertainty}.{source_text}"
        )
