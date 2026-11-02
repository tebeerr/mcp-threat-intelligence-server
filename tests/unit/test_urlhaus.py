from urllib.parse import parse_qs

import httpx
import pytest

from ti_mcp.config import Settings
from ti_mcp.connectors.urlhaus import URLhausConnector
from ti_mcp.domain.models import ErrorCode, Indicator, IndicatorType, SourceStatus


def settings(key="test-key"):
    return Settings(urlhaus_auth_key=key, urlhaus_base_url="https://urlhaus.example/v1")


async def lookup(indicator, handler, key="test-key"):
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        return await URLhausConnector(settings(key), client).lookup(indicator)


@pytest.mark.asyncio
async def test_url_lookup_maps_evidence():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={
            "query_status": "ok",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
            "url_status": "online",
            "date_added": "2026-01-19 01:33:26 UTC",
            "last_online": None,
            "threat": "malware_download",
            "tags": ["elf", "Mozi"],
        })

    result = await lookup(Indicator(type=IndicatorType.URL, value="https://bad.example/x"), handler)

    assert str(requests[0].url) == "https://urlhaus.example/v1/url/"
    assert requests[0].headers["Auth-Key"] == "test-key"
    assert parse_qs(requests[0].content.decode()) == {"url": ["https://bad.example/x"]}
    assert result.is_malicious is True
    assert result.source_reference == "https://urlhaus.abuse.ch/url/1/"
    assert result.tags == ["Mozi", "elf", "malware_download"]
    assert result.first_seen.utcoffset().total_seconds() == 0
    assert result.note == "URL status: online"


@pytest.mark.asyncio
async def test_host_lookup_collects_tags_from_urls():
    def handler(request):
        assert parse_qs(request.content.decode()) == {"host": ["bad.example"]}
        return httpx.Response(200, json={
            "query_status": "ok",
            "urlhaus_reference": "https://urlhaus.abuse.ch/host/bad.example/",
            "firstseen": "2026-01-01 00:00:00 UTC",
            "url_count": "2",
            "urls": [{"tags": ["emotet"], "threat": "malware_download"}, {"tags": None}],
        })

    result = await lookup(Indicator(type=IndicatorType.DOMAIN, value="bad.example"), handler)

    assert result.is_malicious is True
    assert result.tags == ["emotet", "malware_download"]


@pytest.mark.asyncio
async def test_payload_lookup_never_exposes_the_sample_download_link():
    def handler(request):
        assert "sha256_hash" in parse_qs(request.content.decode())
        return httpx.Response(200, json={
            "query_status": "ok",
            "signature": "Gozi",
            "firstseen": "2026-01-19 13:59:06",
            "lastseen": "2026-01-20 13:59:06",
            "url_count": "1",
            "urlhaus_download": "https://urlhaus-api.abuse.ch/v1/download/deadbeef/",
            "urls": [{"urlhaus_reference": "https://urlhaus.abuse.ch/url/9/"}],
        })

    result = await lookup(Indicator(type=IndicatorType.SHA256, value="a" * 64), handler)

    assert result.tags == ["Gozi"]
    assert result.source_reference == "https://urlhaus.abuse.ch/url/9/"
    assert "download" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_no_results_is_a_clean_negative():
    result = await lookup(
        Indicator(type=IndicatorType.IPV4, value="203.0.113.10"),
        lambda request: httpx.Response(200, json={"query_status": "no_results"}),
    )

    assert result.status == SourceStatus.OK
    assert result.is_malicious is False


@pytest.mark.asyncio
async def test_ipv6_gives_no_verdict_and_no_request():
    result = await lookup(
        Indicator(type=IndicatorType.IPV6, value="2001:db8::1"),
        lambda request: pytest.fail("unexpected outbound request"),
    )

    assert result.status == SourceStatus.OK
    assert result.is_malicious is None


@pytest.mark.asyncio
async def test_missing_key_does_not_make_a_request():
    result = await lookup(
        Indicator(type=IndicatorType.IPV4, value="203.0.113.10"),
        lambda request: pytest.fail("unexpected outbound request"),
        key=None,
    )

    assert result.error_code == ErrorCode.SOURCE_UNAVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx.Response(429), ErrorCode.SOURCE_RATE_LIMITED),
        (httpx.Response(401, json={"error": "Unauthorized"}), ErrorCode.SOURCE_UNAVAILABLE),
        (httpx.Response(200, json={"query_status": "invalid_host"}), ErrorCode.SOURCE_UNAVAILABLE),
        (httpx.Response(200, text="not json"), ErrorCode.SOURCE_UNAVAILABLE),
    ],
)
async def test_failures_are_classified(response, expected):
    result = await lookup(
        Indicator(type=IndicatorType.DOMAIN, value="bad.example"), lambda request: response
    )

    assert result.status == SourceStatus.ERROR
    assert result.error_code == expected
