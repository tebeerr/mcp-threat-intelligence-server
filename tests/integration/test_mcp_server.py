from datetime import datetime, timezone

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from ti_mcp.domain.analysis import AnalysisService
from ti_mcp.domain.models import Indicator, SourceResult, SourceStatus
from ti_mcp.server import create_server


class StubConnector:
    name = "stub"

    async def lookup(self, indicator: Indicator) -> SourceResult:
        return SourceResult(
            name=self.name,
            status=SourceStatus.OK,
            retrieved_at=datetime.now(timezone.utc),
            is_malicious=False,
        )


@pytest.mark.asyncio
async def test_mcp_tool_is_discoverable_and_returns_structured_report():
    server = create_server(AnalysisService([StubConnector()]))

    async with create_connected_server_and_client_session(server) as client:
        listed = await client.list_tools()
        result = await client.call_tool("analyze_indicator", {"value": "example.com"})

    assert [tool.name for tool in listed.tools] == ["analyze_indicator"]
    assert result.isError is False
    report = result.structuredContent["result"]
    assert report["indicator"]["value"] == "example.com"
    assert report["risk"]["rule"] == "R3"


@pytest.mark.asyncio
async def test_mcp_tool_returns_structured_validation_error():
    server = create_server(AnalysisService([StubConnector()]))

    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("analyze_indicator", {"value": "not an IOC!"})

    assert result.isError is False
    assert result.structuredContent["result"]["error"]["code"] == "INVALID_INPUT"