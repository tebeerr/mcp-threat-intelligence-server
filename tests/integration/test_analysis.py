from datetime import datetime, timezone

import pytest

from ti_mcp.domain.analysis import AnalysisService
from ti_mcp.domain.models import ErrorCode, Indicator, SourceResult, SourceStatus
from ti_mcp.domain.validation import IndicatorValidationError


class StubConnector:
    name = "stub"

    def __init__(self, result=None):
        self.result = result
        self.calls = 0

    async def lookup(self, indicator: Indicator) -> SourceResult:
        self.calls += 1
        return self.result


@pytest.mark.asyncio
async def test_invalid_indicator_is_rejected_before_connector_call():
    connector = StubConnector()
    service = AnalysisService([connector])

    with pytest.raises(IndicatorValidationError):
        await service.analyze("not a valid IOC!")

    assert connector.calls == 0


@pytest.mark.asyncio
async def test_source_error_returns_partial_report_and_explanation():
    connector = StubConnector(SourceResult(
        name="stub",
        status=SourceStatus.ERROR,
        retrieved_at=datetime.now(timezone.utc),
        error_code=ErrorCode.SOURCE_TIMEOUT,
    ))
    report = await AnalysisService([connector]).analyze("example.com")

    assert report.status == "partial"
    assert report.risk.rule == "R4"
    assert report.sources[0].error_code == ErrorCode.SOURCE_TIMEOUT
