from datetime import datetime, timezone

import pytest

from ti_mcp.domain.models import ErrorCode, Indicator, IndicatorType, SourceResult, SourceStatus
from ti_mcp.storage.cache import CachedConnector, SQLiteCache

INDICATOR = Indicator(type=IndicatorType.DOMAIN, value="threat.example")
RETRIEVED = datetime(2026, 1, 1, tzinfo=timezone.utc)


class CountingConnector:
    name = "stub"

    def __init__(self, status=SourceStatus.OK):
        self.calls = 0
        self.status = status

    async def lookup(self, indicator):
        self.calls += 1
        ok = self.status == SourceStatus.OK
        return SourceResult(
            name=self.name,
            status=self.status,
            retrieved_at=RETRIEVED,
            is_malicious=True if ok else None,
            error_code=None if ok else ErrorCode.SOURCE_TIMEOUT,
        )


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


@pytest.mark.asyncio
async def test_hit_is_flagged_and_keeps_original_retrieval_date(tmp_path):
    connector = CountingConnector()
    cached = CachedConnector(connector, SQLiteCache(tmp_path / "c.sqlite3", 60))

    first = await cached.lookup(INDICATOR)
    second = await cached.lookup(INDICATOR)

    assert connector.calls == 1
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.retrieved_at == RETRIEVED
    assert second.is_malicious is True


@pytest.mark.asyncio
async def test_entry_expires_after_ttl(tmp_path):
    clock = Clock()
    connector = CountingConnector()
    cached = CachedConnector(connector, SQLiteCache(tmp_path / "c.sqlite3", 60, clock))

    await cached.lookup(INDICATOR)
    clock.now += 61
    result = await cached.lookup(INDICATOR)

    assert connector.calls == 2
    assert result.from_cache is False


@pytest.mark.asyncio
async def test_errors_are_never_cached(tmp_path):
    connector = CountingConnector(SourceStatus.ERROR)
    cached = CachedConnector(connector, SQLiteCache(tmp_path / "c.sqlite3", 60))

    await cached.lookup(INDICATOR)
    await cached.lookup(INDICATOR)

    assert connector.calls == 2


@pytest.mark.asyncio
async def test_corrupt_database_degrades_to_live_lookup(tmp_path):
    path = tmp_path / "c.sqlite3"
    path.write_bytes(b"this is not a sqlite database, at all" * 100)
    connector = CountingConnector()

    result = await CachedConnector(connector, SQLiteCache(path, 60)).lookup(INDICATOR)

    assert connector.calls == 1
    assert result.status == SourceStatus.OK


def test_sql_metacharacters_are_stored_as_data(tmp_path):
    cache = SQLiteCache(tmp_path / "c.sqlite3", 60)
    indicator = Indicator(type=IndicatorType.URL, value="https://a.example/';DROP TABLE source_cache;--")
    result = SourceResult(name="stub", status=SourceStatus.OK, retrieved_at=RETRIEVED)

    cache.put("stub", indicator, result)

    assert cache.get("stub", indicator) is not None
