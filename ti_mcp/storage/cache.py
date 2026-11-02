"""SQLite TTL cache for source results.

Successful answers only: caching an outage would hide recovery of the source.
The cache is an optimisation, so any storage failure degrades to a live lookup.
"""

import asyncio
from contextlib import closing
import logging
from pathlib import Path
import sqlite3
import time
from typing import Callable

from pydantic import ValidationError

from ti_mcp.connectors.base import ThreatIntelConnector
from ti_mcp.domain.models import Indicator, SourceResult, SourceStatus

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS source_cache (
    source TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    payload TEXT NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (source, indicator_type, indicator_value)
)
"""


class SQLiteCache:
    def __init__(
        self, path: Path, ttl_seconds: int, clock: Callable[[], float] = time.time
    ) -> None:
        self._path = path
        self._ttl_seconds = ttl_seconds
        self._clock = clock

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path)
        connection.execute(_SCHEMA)
        return connection

    def get(self, source: str, indicator: Indicator) -> SourceResult | None:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT payload FROM source_cache WHERE source = ? AND indicator_type = ?"
                    " AND indicator_value = ? AND expires_at > ?",
                    (source, indicator.type.value, indicator.value, self._clock()),
                ).fetchone()
            if row is None:
                return None
            cached = SourceResult.model_validate_json(row[0])
        except (sqlite3.Error, OSError, ValidationError) as exc:
            logger.warning("cache_read_failed", extra={"error_type": type(exc).__name__})
            return None
        return cached.model_copy(update={"from_cache": True})

    def put(self, source: str, indicator: Indicator, result: SourceResult) -> None:
        now = self._clock()
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("DELETE FROM source_cache WHERE expires_at <= ?", (now,))
                connection.execute(
                    "INSERT OR REPLACE INTO source_cache VALUES (?, ?, ?, ?, ?)",
                    (
                        source,
                        indicator.type.value,
                        indicator.value,
                        result.model_dump_json(),
                        now + self._ttl_seconds,
                    ),
                )
        except (sqlite3.Error, OSError) as exc:
            logger.warning("cache_write_failed", extra={"error_type": type(exc).__name__})


class CachedConnector:
    """Decorates a connector; `retrieved_at` keeps the original retrieval date."""

    def __init__(self, connector: ThreatIntelConnector, cache: SQLiteCache) -> None:
        self._connector = connector
        self._cache = cache
        self.name = connector.name

    async def lookup(self, indicator: Indicator) -> SourceResult:
        cached = await asyncio.to_thread(self._cache.get, self.name, indicator)
        if cached is not None:
            return cached
        result = await self._connector.lookup(indicator)
        if result.status == SourceStatus.OK:
            await asyncio.to_thread(self._cache.put, self.name, indicator, result)
        return result
