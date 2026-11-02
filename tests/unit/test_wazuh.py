import json

import httpx
import pytest

from ti_mcp.config import Settings
from ti_mcp.connectors.wazuh import WazuhIndexerConnector
from ti_mcp.domain.errors import ServiceError


def settings(**overrides):
    values = {
        "wazuh_indexer_url": "https://indexer.lab:9200",
        "wazuh_username": "ti_reader",
        "wazuh_password": "s3cret-value",
    }
    return Settings(**{**values, **overrides})


def connector(handler, **overrides):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return WazuhIndexerConnector(settings(**overrides), client)


def hits(*documents):
    return httpx.Response(200, json={"hits": {"hits": [{"_source": d} for d in documents]}})


@pytest.mark.asyncio
async def test_list_uses_search_only_and_never_fetches_raw_logs():
    seen = []

    def handler(request):
        seen.append(request)
        return hits({"id": "1.1"})

    alerts = await connector(handler).list_alerts(limit=5, min_level=7, since_hours=2)

    assert alerts == [{"id": "1.1"}]
    request = seen[0]
    assert request.url.path == "/wazuh-alerts-*/_search"
    assert request.headers["authorization"].startswith("Basic ")
    body = json.loads(request.content)
    assert body["size"] == 5
    assert "full_log" not in body["_source"] and "data" not in body["_source"]
    assert {"range": {"rule.level": {"gte": 7}}} in body["query"]["bool"]["filter"]
    assert {"range": {"timestamp": {"gte": "now-2h"}}} in body["query"]["bool"]["filter"]


@pytest.mark.asyncio
async def test_get_alert_and_not_found():
    wazuh = connector(lambda request: hits({"id": "1.1"}))
    assert (await wazuh.get_alert("1.1"))["id"] == "1.1"

    with pytest.raises(ServiceError) as error:
        await connector(lambda request: hits()).get_alert("1.1")
    assert error.value.code == "ALERT_NOT_FOUND"


@pytest.mark.asyncio
async def test_unconfigured_connector_makes_no_request():
    with pytest.raises(ServiceError) as error:
        await connector(
            lambda request: pytest.fail("unexpected request"), wazuh_password=None
        ).get_alert("1.1")

    assert error.value.code == "SOURCE_UNAVAILABLE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "SOURCE_UNAVAILABLE"), (403, "SOURCE_UNAVAILABLE"),
     (429, "SOURCE_RATE_LIMITED"), (500, "SOURCE_UNAVAILABLE")],
)
async def test_http_errors_are_sanitized(status, code):
    wazuh = connector(lambda request: httpx.Response(status, text="internal cluster details"))

    with pytest.raises(ServiceError) as error:
        await wazuh.get_alert("1.1")

    assert error.value.code == code
    assert "cluster" not in str(error.value)


@pytest.mark.asyncio
async def test_timeout_is_classified():
    def handler(request):
        raise httpx.ReadTimeout("details")

    with pytest.raises(ServiceError) as error:
        await connector(handler).get_alert("1.1")

    assert error.value.code == "SOURCE_TIMEOUT"


def test_password_is_not_in_settings_repr():
    assert "s3cret-value" not in repr(settings())
