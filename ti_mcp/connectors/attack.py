"""MITRE ATT&CK lookups against a local STIX bundle: no network at query time."""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

from ti_mcp.connectors.base import parse_timestamp
from ti_mcp.domain.errors import ServiceError
from ti_mcp.domain.models import AttackTechnique, ErrorCode

_DESCRIPTION_LIMIT = 1500


def load_techniques(path: Path) -> dict[str, AttackTechnique]:
    """Index a STIX bundle by technique id. Raises ServiceError when unusable."""
    try:
        with path.open(encoding="utf-8") as stream:
            bundle = json.load(stream)
        downloaded_at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    except (OSError, ValueError) as exc:
        raise ServiceError(
            ErrorCode.SOURCE_UNAVAILABLE,
            "ATT&CK data is missing or unreadable; run ti-mcp-sync-attack",
        ) from exc

    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ServiceError(
            ErrorCode.SOURCE_UNAVAILABLE,
            "ATT&CK data is not a STIX bundle; run ti-mcp-sync-attack",
        )

    techniques: dict[str, AttackTechnique] = {}
    for item in objects:
        technique = _to_technique(item, downloaded_at)
        if technique is None:
            continue
        current = techniques.get(technique.id)
        # An id can survive on a revoked object next to its live replacement.
        if current is None or current.revoked:
            techniques[technique.id] = technique
    return techniques


def _to_technique(item: object, downloaded_at: datetime) -> AttackTechnique | None:
    if not isinstance(item, dict) or item.get("type") != "attack-pattern":
        return None
    reference = next(
        (
            entry
            for entry in item.get("external_references") or []
            if isinstance(entry, dict) and entry.get("source_name") == "mitre-attack"
        ),
        None,
    )
    if reference is None or not isinstance(reference.get("external_id"), str):
        return None
    return AttackTechnique(
        id=reference["external_id"],
        name=str(item.get("name", "")),
        description=str(item.get("description", ""))[:_DESCRIPTION_LIMIT],
        tactics=sorted(
            phase["phase_name"]
            for phase in item.get("kill_chain_phases") or []
            if isinstance(phase, dict)
            and phase.get("kill_chain_name") == "mitre-attack"
            and isinstance(phase.get("phase_name"), str)
        ),
        platforms=[p for p in item.get("x_mitre_platforms") or [] if isinstance(p, str)],
        url=reference.get("url") if isinstance(reference.get("url"), str) else None,
        deprecated=item.get("x_mitre_deprecated") is True,
        revoked=item.get("revoked") is True,
        data_modified=parse_timestamp(item.get("modified")),
        retrieved_at=downloaded_at,
    )


class AttackCatalog:
    """Lazy catalog: the ~50 MB bundle is parsed once, off the event loop.

    A failed load is not remembered, so running the sync command fixes a live
    server without a restart.
    """

    def __init__(self, stix_path: Path) -> None:
        self._path = stix_path
        self._techniques: dict[str, AttackTechnique] | None = None
        self._lock = asyncio.Lock()

    async def get(self, technique_id: str) -> AttackTechnique | None:
        if self._techniques is None:
            async with self._lock:
                if self._techniques is None:
                    self._techniques = await asyncio.to_thread(load_techniques, self._path)
        return self._techniques.get(technique_id)
