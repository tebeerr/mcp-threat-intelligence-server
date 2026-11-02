import json

import httpx
import pytest

from ti_mcp.attack_sync import sync_attack_bundle
from ti_mcp.connectors.attack import AttackCatalog
from ti_mcp.domain.errors import ServiceError

from tests.fixtures import STIX_BUNDLE


@pytest.fixture
def bundle_path(tmp_path):
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(STIX_BUNDLE), encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_technique_is_mapped_and_live_object_beats_revoked_one(bundle_path):
    technique = await AttackCatalog(bundle_path).get("T1059.001")

    assert technique.name == "PowerShell"
    assert technique.revoked is False
    assert technique.tactics == ["execution"]
    assert technique.platforms == ["Windows"]
    assert technique.source == "mitre_attack_stix"
    assert technique.data_modified.year == 2025


@pytest.mark.asyncio
async def test_unknown_technique_returns_none(bundle_path):
    assert await AttackCatalog(bundle_path).get("T0000") is None


@pytest.mark.asyncio
async def test_missing_bundle_is_an_actionable_error_that_recovers(tmp_path):
    path = tmp_path / "attack.json"
    catalog = AttackCatalog(path)

    with pytest.raises(ServiceError) as error:
        await catalog.get("T1059.001")
    assert "ti-mcp-sync-attack" in str(error.value)

    path.write_text(json.dumps(STIX_BUNDLE), encoding="utf-8")
    assert (await catalog.get("T1059.001")).name == "PowerShell"


@pytest.mark.asyncio
async def test_sync_replaces_bundle_only_after_validation(tmp_path):
    target = tmp_path / "data" / "attack.json"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=STIX_BUNDLE))
    async with httpx.AsyncClient(transport=transport) as client:
        assert await sync_attack_bundle(target, client) == 1
    good = target.read_bytes()

    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html>oops</html>"))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ServiceError):
            await sync_attack_bundle(target, client)

    assert target.read_bytes() == good
    assert [path.name for path in target.parent.iterdir()] == ["attack.json"]
