"""Read-only access to Wazuh alerts through the Wazuh indexer search API.

Alerts live in the indexer (port 9200), not in the Wazuh server API (55000).
Only `_search` is ever called; pair it with an account limited to read access
on the alert indices (see docs/wazuh-lab.md).
"""

import ssl
from typing import Any
from urllib.parse import quote

import httpx

from ti_mcp.config import Settings
from ti_mcp.domain.errors import ServiceError
from ti_mcp.domain.models import ErrorCode

# Listing never needs raw logs: they stay out of the response, and out of the LLM.
_SUMMARY_FIELDS = ["id", "timestamp", "rule", "agent.id", "agent.name"]


class WazuhIndexerConnector:
    name = "wazuh_indexer"

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._client = client

    async def list_alerts(
        self, limit: int, min_level: int, since_hours: int
    ) -> list[dict[str, Any]]:
        return await self._search({
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": _SUMMARY_FIELDS,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"range": {"timestamp": {"gte": f"now-{since_hours}h"}}},
                    ]
                }
            },
        })

    async def get_alert(self, alert_id: str) -> dict[str, Any]:
        hits = await self._search({"size": 1, "query": {"term": {"id": alert_id}}})
        if not hits:
            raise ServiceError(ErrorCode.ALERT_NOT_FOUND, "No Wazuh alert has this id")
        return hits[0]

    async def _search(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        settings = self._settings
        if not (settings.wazuh_indexer_url and settings.wazuh_username and settings.wazuh_password):
            raise ServiceError(
                ErrorCode.SOURCE_UNAVAILABLE,
                "Wazuh is not configured: set WAZUH_INDEXER_URL, WAZUH_USERNAME, WAZUH_PASSWORD",
            )

        client = self._client or self._new_client()
        should_close = self._client is None
        url = f"{settings.wazuh_indexer_url}/{quote(settings.wazuh_alert_index, safe='*-,')}/_search"
        try:
            response = await client.post(
                url,
                json=body,
                auth=(settings.wazuh_username, settings.wazuh_password),
            )
            if response.status_code in (401, 403):
                raise ServiceError(
                    ErrorCode.SOURCE_UNAVAILABLE, "Wazuh indexer rejected the credentials"
                )
            if response.status_code == 429:
                raise ServiceError(ErrorCode.SOURCE_RATE_LIMITED, "Wazuh indexer is rate limiting")
            response.raise_for_status()
            payload = response.json()
        except httpx.TimeoutException as exc:
            raise ServiceError(ErrorCode.SOURCE_TIMEOUT, "Wazuh indexer timed out") from exc
        except (httpx.HTTPError, ValueError, ssl.SSLError) as exc:
            raise ServiceError(
                ErrorCode.SOURCE_UNAVAILABLE, "Wazuh indexer is unavailable"
            ) from exc
        finally:
            if should_close:
                await client.aclose()

        hits = payload.get("hits", {}).get("hits") if isinstance(payload, dict) else None
        if not isinstance(hits, list):
            raise ServiceError(ErrorCode.SOURCE_UNAVAILABLE, "Unexpected Wazuh indexer response")
        return [
            hit["_source"]
            for hit in hits
            if isinstance(hit, dict) and isinstance(hit.get("_source"), dict)
        ]

    def _new_client(self) -> httpx.AsyncClient:
        settings = self._settings
        try:
            # Lab indexers use a private CA: trust it explicitly, never disable TLS checks.
            verify: ssl.SSLContext | bool = (
                ssl.create_default_context(cafile=settings.wazuh_ca_bundle)
                if settings.wazuh_ca_bundle
                else True
            )
        except (OSError, ssl.SSLError) as exc:
            raise ServiceError(
                ErrorCode.SOURCE_UNAVAILABLE, "WAZUH_CA_BUNDLE could not be loaded"
            ) from exc
        return httpx.AsyncClient(
            timeout=settings.wazuh_timeout_seconds,
            follow_redirects=False,
            verify=verify,
        )
