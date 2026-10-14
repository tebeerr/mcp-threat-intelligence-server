"""Protocol-independent analysis orchestration."""

import asyncio
import logging
from datetime import datetime, timezone
from time import perf_counter

from ti_mcp.connectors.base import ThreatIntelConnector
from ti_mcp.domain.correlation import correlate
from ti_mcp.domain.models import ErrorCode, Indicator, Report, SourceResult, SourceStatus
from ti_mcp.domain.risk import assess_risk
from ti_mcp.domain.validation import IndicatorValidationError, validate_indicator

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(self, connectors: list[ThreatIntelConnector], max_indicator_length: int = 2048):
        self._connectors = connectors
        self._max_indicator_length = max_indicator_length

    async def analyze(self, value: str) -> Report:
        indicator = validate_indicator(value, self._max_indicator_length)
        tasks = [self._lookup(connector, indicator) for connector in self._connectors]
        results = await asyncio.gather(*tasks)
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
            limits=["Passive threat-intelligence lookup only", "No direct contact with the indicator"],
        )

    async def _lookup(self, connector: ThreatIntelConnector, indicator: Indicator) -> SourceResult:
        started = perf_counter()
        try:
            result = await connector.lookup(indicator)
        except Exception:
            result = SourceResult(
                name=connector.name,
                status=SourceStatus.ERROR,
                retrieved_at=datetime.now(timezone.utc),
                error_code=ErrorCode.SOURCE_UNAVAILABLE,
            )
        logger.info(
            "source_lookup_complete",
            extra={
                "source": connector.name,
                "status": result.status.value,
                "error_code": result.error_code.value if result.error_code else None,
                "duration_ms": round((perf_counter() - started) * 1000, 2),
            },
        )
        return result

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
