"""AlienVault OTX passive indicator lookup connector."""

from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from ti_mcp.config import Settings
from ti_mcp.domain.models import ErrorCode, Indicator, IndicatorType, SourceResult, SourceStatus


class OTXConnector:
    name = "alienvault_otx"

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._client = client

    async def lookup(self, indicator: Indicator) -> SourceResult:
        retrieved_at = datetime.now(timezone.utc)
        if not self._settings.otx_api_key:
            return self._error(retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)

        type_path = {
            IndicatorType.IPV4: "IPv4",
            IndicatorType.IPV6: "IPv6",
            IndicatorType.DOMAIN: "domain",
            IndicatorType.URL: "url",
            IndicatorType.SHA256: "file",
        }[indicator.type]
        endpoint = (
            f"{self._settings.otx_base_url}/indicators/{type_path}/"
            f"{quote(indicator.value, safe='')}/general"
        )
        client = self._client or httpx.AsyncClient(
            timeout=self._settings.otx_timeout_seconds,
            follow_redirects=False,
        )
        should_close = self._client is None

        try:
            response = await client.get(
                endpoint,
                headers={"X-OTX-API-KEY": self._settings.otx_api_key},
            )
            if response.status_code == 429:
                return self._error(retrieved_at, ErrorCode.SOURCE_RATE_LIMITED)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                return self._error(retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)
            return self._map_response(payload, retrieved_at)
        except httpx.TimeoutException:
            return self._error(retrieved_at, ErrorCode.SOURCE_TIMEOUT)
        except (httpx.HTTPError, ValueError):
            return self._error(retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)
        finally:
            if should_close:
                await client.aclose()

    def _map_response(self, payload: dict, retrieved_at: datetime) -> SourceResult:
        pulse_info = payload.get("pulse_info")
        if not isinstance(pulse_info, dict):
            return self._error(retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)
        pulses = pulse_info.get("pulses", [])
        if not isinstance(pulses, list):
            return self._error(retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)

        tags: set[str] = set()
        references: list[str] = []
        first_seen: list[datetime] = []
        last_seen: list[datetime] = []
        for pulse in pulses:
            if not isinstance(pulse, dict):
                continue
            pulse_id = pulse.get("id")
            if isinstance(pulse_id, str) and pulse_id:
                references.append(pulse_id)
            pulse_tags = pulse.get("tags", [])
            if isinstance(pulse_tags, list):
                tags.update(tag for tag in pulse_tags if isinstance(tag, str))
            for field, values in (("created", first_seen), ("modified", last_seen)):
                timestamp = pulse.get(field)
                if isinstance(timestamp, str):
                    try:
                        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    values.append(parsed)

        return SourceResult(
            name=self.name,
            status=SourceStatus.OK,
            source_reference=references[0] if references else None,
            first_seen=min(first_seen) if first_seen else None,
            last_seen=max(last_seen) if last_seen else None,
            retrieved_at=retrieved_at,
            tags=sorted(tags),
            is_malicious=bool(pulses),
        )

    def _error(self, retrieved_at: datetime, code: ErrorCode) -> SourceResult:
        return SourceResult(
            name=self.name,
            status=SourceStatus.ERROR,
            retrieved_at=retrieved_at,
            error_code=code,
        )
