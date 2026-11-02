"""Full path over MCP: Wazuh alert -> IOC extraction -> OTX and URLhaus -> report."""

import asyncio
from datetime import datetime, timezone
import json
from urllib.parse import parse_qs, unquote

import httpx
from mcp.shared.memory import create_connected_server_and_client_session
import pytest

from ti_mcp.config import Settings
from ti_mcp.connectors.attack import AttackCatalog
from ti_mcp.connectors.otx import OTXConnector
from ti_mcp.connectors.urlhaus import URLhausConnector
from ti_mcp.connectors.wazuh import WazuhIndexerConnector
from ti_mcp.domain.alerts import AlertAnalysisService
from ti_mcp.domain.analysis import AnalysisService
from ti_mcp.domain.models import ErrorCode, SourceResult, SourceStatus
from ti_mcp.server import create_server

from tests.fixtures import LAB_IP, PUBLIC_IP, SHA256, STIX_BUNDLE, SYSMON_ALERT

SETTINGS = Settings(
    otx_api_key="otx",
    urlhaus_auth_key="urlhaus",
    wazuh_indexer_url="https://indexer.lab:9200",
    wazuh_username="ti_reader",
    wazuh_password="pw",
)


class World:
    """One mock transport standing in for the indexer and both TI providers."""

    def __init__(self):
        self.external = []
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        host = request.url.host
        if host == "indexer.lab":
            return httpx.Response(200, json={"hits": {"hits": [{"_source": SYSMON_ALERT}]}})
        if host == "otx.alienvault.com":
            self.external.append(unquote(request.url.raw_path.decode()))
            malicious = PUBLIC_IP in self.external[-1]
            return httpx.Response(200, json={
                "pulse_info": {"pulses": [{"id": "pulse-1", "tags": ["C2"]}] if malicious else []}
            })
        self.external.append(request.content.decode())
        listed = PUBLIC_IP in parse_qs(request.content.decode()).get("host", [])
        return httpx.Response(200, json=(
            {"query_status": "ok", "url_count": "1", "urls": []}
            if listed
            else {"query_status": "no_results"}
        ))

    def server(self, tmp_path):
        bundle = tmp_path / "attack.json"
        bundle.write_text(json.dumps(STIX_BUNDLE), encoding="utf-8")
        service = AnalysisService([
            OTXConnector(SETTINGS, self.client),
            URLhausConnector(SETTINGS, self.client),
        ])
        catalog = AttackCatalog(bundle)
        alerts = AlertAnalysisService(
            WazuhIndexerConnector(SETTINGS, self.client), service, catalog
        )
        return create_server(service, alerts, catalog)


async def call(server, tool, arguments):
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool(tool, arguments)
    assert result.isError is False, result.content
    return result.structuredContent["result"]


@pytest.mark.asyncio
async def test_analyze_alert_end_to_end(tmp_path):
    world = World()

    report = await call(world.server(tmp_path), "analyze_alert", {"alert_id": "1761900000.4242"})

    assert report["alert"]["id"] == "1761900000.4242"
    assert report["alert"]["rule_level"] == 12
    by_value = {item["report"]["indicator"]["value"]: item for item in report["indicators"]}
    assert set(by_value) == {
        PUBLIC_IP, "c2.threat.example", SHA256, "https://threat.example/payload.ps1",
    }
    assert by_value[PUBLIC_IP]["field"] == "data.win.eventdata.destinationIp"
    assert report["risk"]["level"] == "high"
    assert report["risk"]["rule"] == "R1"
    assert PUBLIC_IP in report["risk"]["explanation"]
    assert [t["id"] for t in report["techniques"]] == ["T1059.001"]
    assert report["unresolved_techniques"] == ["T9999"]
    assert report["status"] == "partial"


@pytest.mark.asyncio
async def test_lab_data_never_reaches_external_sources(tmp_path):
    world = World()

    await call(world.server(tmp_path), "analyze_alert", {"alert_id": "1.1"})

    outbound = " ".join(world.external)
    assert world.external
    assert LAB_IP not in outbound
    assert "10.0.0.9" not in outbound
    assert "win-lab-01" not in outbound


@pytest.mark.asyncio
async def test_raw_alert_text_is_not_returned_to_the_llm(tmp_path):
    report = await call(World().server(tmp_path), "analyze_alert", {"alert_id": "1.1"})

    assert "Ignore previous instructions" not in json.dumps(report)


@pytest.mark.asyncio
async def test_rule_level_does_not_influence_risk(tmp_path):
    alert = {"id": "2.2", "rule": {"level": 15, "description": "x"}}

    class OneAlert:
        async def get_alert(self, alert_id):
            return alert

        async def list_alerts(self, limit, min_level, since_hours):
            return [alert]

    report = await AlertAnalysisService(OneAlert(), AnalysisService([])).analyze_alert("2.2")

    assert report.risk.level == "indeterminate"
    assert report.indicators == []


@pytest.mark.asyncio
async def test_indicator_limit_is_reported(tmp_path):
    class Stub:
        name = "stub"

        async def lookup(self, indicator):
            return SourceResult(
                name=self.name, status=SourceStatus.OK,
                retrieved_at=datetime.now(timezone.utc), is_malicious=False,
            )

    class OneAlert:
        async def get_alert(self, alert_id):
            return {"id": "3.3", "full_log": "198.51.100.1 198.51.100.2 198.51.100.3"}

    service = AlertAnalysisService(OneAlert(), AnalysisService([Stub()]), max_indicators=2)
    report = await service.analyze_alert("3.3")

    assert len(report.indicators) == 2
    assert report.not_analyzed == 1
    assert report.status == "partial"


@pytest.mark.asyncio
async def test_other_tools_over_mcp(tmp_path):
    server = World().server(tmp_path)

    listed = await call(server, "list_wazuh_alerts", {"limit": 5})
    technique = await call(server, "get_attack_technique", {"technique_id": "t1059.001"})
    unknown = await call(server, "get_attack_technique", {"technique_id": "T0000"})
    invalid = await call(server, "get_attack_technique", {"technique_id": "nope"})
    lookup = await call(
        server, "lookup_indicator", {"value": PUBLIC_IP, "sources": ["urlhaus"]}
    )
    bad_source = await call(server, "lookup_indicator", {"value": PUBLIC_IP, "sources": ["nope"]})
    bad_alert = await call(server, "analyze_alert", {"alert_id": "../../_cat"})
    private = await call(server, "analyze_indicator", {"value": LAB_IP})

    assert listed["count"] == 1
    assert "full_log" not in listed["alerts"][0]
    assert technique["name"] == "PowerShell"
    assert unknown["error"]["code"] == "TECHNIQUE_NOT_FOUND"
    assert invalid["error"]["code"] == "INVALID_INPUT"
    assert [source["name"] for source in lookup["sources"]] == ["urlhaus"]
    assert "risk" not in lookup
    assert bad_source["error"]["code"] == "INVALID_INPUT"
    assert bad_alert["error"]["code"] == "INVALID_INPUT"
    assert private["error"]["code"] == "INVALID_INPUT"


@pytest.mark.asyncio
async def test_unconfigured_wazuh_and_catalog_give_structured_errors():
    server = create_server(AnalysisService([]))

    listed = await call(server, "list_wazuh_alerts", {})
    technique = await call(server, "get_attack_technique", {"technique_id": "T1059"})

    assert listed["error"]["code"] == "SOURCE_UNAVAILABLE"
    assert technique["error"]["code"] == "SOURCE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_unexpected_exception_text_does_not_reach_the_client():
    class Exploding:
        async def get_alert(self, alert_id):
            raise RuntimeError("secret internal detail")

    service = AnalysisService([])
    server = create_server(service, AlertAnalysisService(Exploding(), service))

    result = await call(server, "analyze_alert", {"alert_id": "1.1"})

    assert result["error"]["code"] == "INTERNAL_ERROR"
    assert "secret" not in result["error"]["message"]


@pytest.mark.asyncio
async def test_hung_source_is_bounded_and_named_while_others_answer():
    class Hung:
        name = "hung"

        async def lookup(self, indicator):
            await asyncio.sleep(30)

    class Healthy:
        name = "healthy"

        async def lookup(self, indicator):
            return SourceResult(
                name=self.name, status=SourceStatus.OK,
                retrieved_at=datetime.now(timezone.utc), is_malicious=True,
            )

    report = await AnalysisService(
        [Hung(), Healthy()], source_timeout_seconds=0.01
    ).analyze("threat.example")

    assert report.status == "partial"
    hung = next(source for source in report.sources if source.name == "hung")
    assert hung.error_code == ErrorCode.SOURCE_TIMEOUT
    assert report.risk.rule == "R2"
