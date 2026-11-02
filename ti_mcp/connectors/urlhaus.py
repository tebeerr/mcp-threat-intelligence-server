"""abuse.ch URLhaus passive lookup connector (query API v1)."""

from datetime import datetime, timezone

import httpx

from ti_mcp.config import Settings
from ti_mcp.connectors.base import error_result, parse_timestamp
from ti_mcp.domain.models import ErrorCode, Indicator, IndicatorType, SourceResult, SourceStatus


class URLhausConnector:
    name = "urlhaus"

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._client = client

    async def lookup(self, indicator: Indicator) -> SourceResult:
        retrieved_at = datetime.now(timezone.utc)
        if not self._settings.urlhaus_auth_key:
            return error_result(self.name, retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)
        if indicator.type == IndicatorType.IPV6:
            return SourceResult(
                name=self.name,
                status=SourceStatus.OK,
                retrieved_at=retrieved_at,
                note="URLhaus host lookups do not cover IPv6: no verdict",
            )

        path, form = {
            IndicatorType.IPV4: ("host", {"host": indicator.value}),
            IndicatorType.DOMAIN: ("host", {"host": indicator.value}),
            IndicatorType.URL: ("url", {"url": indicator.value}),
            IndicatorType.SHA256: ("payload", {"sha256_hash": indicator.value}),
        }[indicator.type]
        client = self._client or httpx.AsyncClient(
            timeout=self._settings.urlhaus_timeout_seconds,
            follow_redirects=False,
        )
        should_close = self._client is None

        try:
            response = await client.post(
                f"{self._settings.urlhaus_base_url}/{path}/",
                data=form,
                headers={"Auth-Key": self._settings.urlhaus_auth_key},
            )
            if response.status_code == 429:
                return error_result(self.name, retrieved_at, ErrorCode.SOURCE_RATE_LIMITED)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                return error_result(self.name, retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)
            return self._map_response(path, payload, retrieved_at)
        except httpx.TimeoutException:
            return error_result(self.name, retrieved_at, ErrorCode.SOURCE_TIMEOUT)
        except (httpx.HTTPError, ValueError):
            return error_result(self.name, retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)
        finally:
            if should_close:
                await client.aclose()

    def _map_response(self, path: str, payload: dict, retrieved_at: datetime) -> SourceResult:
        status = payload.get("query_status")
        if status == "no_results":
            return SourceResult(
                name=self.name,
                status=SourceStatus.OK,
                retrieved_at=retrieved_at,
                is_malicious=False,
                note="Indicator not listed by URLhaus",
            )
        if status != "ok":
            return error_result(self.name, retrieved_at, ErrorCode.SOURCE_UNAVAILABLE)

        urls = [entry for entry in payload.get("urls") or [] if isinstance(entry, dict)]
        reference = payload.get("urlhaus_reference")
        tags: set[str] = set()
        if path == "url":
            first_seen, last_seen = payload.get("date_added"), payload.get("last_online")
            tags.update(_strings(payload.get("tags")))
            tags.update(_strings([payload.get("threat")]))
            note = f"URL status: {_text(payload.get('url_status'))}"
        elif path == "host":
            first_seen, last_seen = payload.get("firstseen"), None
            for entry in urls:
                tags.update(_strings(entry.get("tags")))
                tags.update(_strings([entry.get("threat")]))
            note = f"{_text(payload.get('url_count'))} malware URL(s) recorded on this host"
        else:
            # `urlhaus_download` is deliberately dropped: it serves the malware
            # sample itself and has no place in a report given to an LLM.
            first_seen, last_seen = payload.get("firstseen"), payload.get("lastseen")
            tags.update(_strings([payload.get("signature")]))
            reference = next(
                (entry.get("urlhaus_reference") for entry in urls if entry.get("urlhaus_reference")),
                None,
            )
            note = f"{_text(payload.get('url_count'))} URL(s) served this payload"

        return SourceResult(
            name=self.name,
            status=SourceStatus.OK,
            source_reference=reference if isinstance(reference, str) else None,
            first_seen=parse_timestamp(first_seen),
            last_seen=parse_timestamp(last_seen),
            retrieved_at=retrieved_at,
            tags=sorted(tags),
            is_malicious=True,
            note=note,
        )


def _strings(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str) and value]


def _text(value: object) -> str:
    return str(value) if isinstance(value, (str, int)) else "unknown"
