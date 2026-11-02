from datetime import datetime, timezone

import httpx
import pytest

from ti_mcp.config import Settings
from ti_mcp.connectors.otx import OTXConnector
from ti_mcp.domain.models import ErrorCode, Indicator, IndicatorType, SourceStatus


def settings(api_key="test-key"):
    return Settings(otx_api_key=api_key, otx_base_url="https://otx.example/api/v1")


@pytest.mark.asyncio
async def test_otx_lookup_maps_evidence_and_encodes_indicator_url():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={
            "pulse_info": {
                "pulses": [{
                    "id": "pulse-123",
                    "tags": ["botnet", "c2"],
                    "created": "2026-10-01T08:00:00Z",
                    "modified": "2026-10-12T10:30:00Z",
                }]
            }
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OTXConnector(settings(), client).lookup(
            Indicator(type=IndicatorType.URL, value="https://bad.example/path?q=1")
        )

    assert requests[0].url.raw_path == (
        b"/api/v1/indicators/url/https%3A%2F%2Fbad.example%2Fpath%3Fq%3D1/general"
    )
    assert requests[0].url.query == b""
    assert requests[0].headers["X-OTX-API-KEY"] == "test-key"
    assert result.status == SourceStatus.OK
    assert result.source_reference == "pulse-123"
    assert result.tags == ["botnet", "c2"]
    assert result.is_malicious is True
    assert result.first_seen == datetime(2026, 10, 1, 8, tzinfo=timezone.utc)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "expected_error"),
    [(429, ErrorCode.SOURCE_RATE_LIMITED), (503, ErrorCode.SOURCE_UNAVAILABLE)],
)
async def test_otx_http_errors_are_sanitized(status_code, expected_error):
    def handler(request):
        return httpx.Response(status_code, text="provider details must not escape")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OTXConnector(settings(), client).lookup(
            Indicator(type=IndicatorType.DOMAIN, value="example.com")
        )

    assert result.status == SourceStatus.ERROR
    assert result.error_code == expected_error
    assert "provider details" not in str(result.model_dump())


@pytest.mark.asyncio
async def test_otx_timeout_is_classified_without_leaking_exception():
    def handler(request):
        raise httpx.ReadTimeout("sensitive request details")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OTXConnector(settings(), client).lookup(
            Indicator(type=IndicatorType.IPV4, value="203.0.113.10")
        )

    assert result.error_code == ErrorCode.SOURCE_TIMEOUT
    assert "sensitive" not in str(result.model_dump())


@pytest.mark.asyncio
async def test_missing_api_key_does_not_make_a_request():
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: pytest.fail("unexpected outbound request")
    )) as client:
        result = await OTXConnector(settings(api_key=None), client).lookup(
            Indicator(type=IndicatorType.IPV4, value="203.0.113.10")
        )

    assert result.error_code == ErrorCode.SOURCE_UNAVAILABLE


@pytest.mark.asyncio
async def test_whitelisted_indicator_with_pulses_is_not_malicious():
    def handler(request):
        return httpx.Response(200, json={
            "validation": [{"source": "whitelist", "name": "Whitelisted domain"}],
            "pulse_info": {"pulses": [{"id": "pulse-1", "tags": ["phishing"]}]},
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OTXConnector(settings(), client).lookup(
            Indicator(type=IndicatorType.DOMAIN, value="google.com")
        )

    assert result.is_malicious is False
    assert "whitelisted" in result.note


@pytest.mark.asyncio
async def test_naive_provider_timestamps_are_read_as_utc():
    def handler(request):
        return httpx.Response(200, json={"pulse_info": {"pulses": [
            {"id": "a", "created": "2021-05-19T15:36:44.966000"},
            {"id": "b", "created": "2022-05-19T15:36:44Z"},
        ]}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OTXConnector(settings(), client).lookup(
            Indicator(type=IndicatorType.DOMAIN, value="threat.example")
        )

    assert result.status == SourceStatus.OK
    assert result.first_seen == datetime(2021, 5, 19, 15, 36, 44, 966000, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_unknown_indicator_404_is_not_an_outage():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(404))
    ) as client:
        result = await OTXConnector(settings(), client).lookup(
            Indicator(type=IndicatorType.SHA256, value="a" * 64)
        )

    assert result.status == SourceStatus.OK
    assert result.is_malicious is False
