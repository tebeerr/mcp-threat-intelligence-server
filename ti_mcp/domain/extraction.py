"""Deterministic IOC extraction from Wazuh alerts.

Every candidate must pass `validate_indicator`, which is what keeps lab
addresses and internal hostnames from reaching external sources. Agent and
manager fields are never read: they describe the lab, not the threat.
"""

import re
from typing import Any

from ti_mcp.domain.models import DiscardedCandidate, ExtractedIndicator
from ti_mcp.domain.validation import IndicatorValidationError, validate_indicator

_STRUCTURED_FIELDS = (
    "data.srcip",
    "data.dstip",
    "data.src_ip",
    "data.dest_ip",
    "data.url",
    "data.http.hostname",
    "data.dns.rrname",
    "data.win.eventdata.destinationIp",
    "data.win.eventdata.sourceIp",
    "data.win.eventdata.destinationHostname",
    "data.win.eventdata.queryName",
    "syscheck.sha256_after",
)
_SYSMON_HASHES_FIELD = "data.win.eventdata.hashes"
# Domains are not searched in free text: file names like `setup.exe` look identical.
_FREE_TEXT_FIELDS = (
    "data.win.eventdata.commandLine",
    "data.audit.command",
    "full_log",
)
_FREE_TEXT_LIMIT = 64 * 1024

_SYSMON_SHA256 = re.compile(r"(?:^|,)\s*SHA256=([A-Fa-f0-9]{64})\b", re.IGNORECASE)
_FREE_TEXT_PATTERNS = (
    re.compile(r"https?://[^\s\"'<>\\)\]]+", re.IGNORECASE),
    re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
)


def _field_values(alert: dict[str, Any], path: str) -> list[str]:
    current: Any = alert
    for key in path.split("."):
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    values = current if isinstance(current, list) else [current]
    return [value.strip() for value in values if isinstance(value, str) and value.strip()]


def _candidates(alert: dict[str, Any]) -> list[tuple[str, str]]:
    found = [
        (field, value) for field in _STRUCTURED_FIELDS for value in _field_values(alert, field)
    ]
    for value in _field_values(alert, _SYSMON_HASHES_FIELD):
        found.extend((_SYSMON_HASHES_FIELD, sha256) for sha256 in _SYSMON_SHA256.findall(value))
    for field in _FREE_TEXT_FIELDS:
        for value in _field_values(alert, field):
            text = value[:_FREE_TEXT_LIMIT]
            for pattern in _FREE_TEXT_PATTERNS:
                found.extend((field, match.rstrip(".,;:")) for match in pattern.findall(text))
    return found


def extract_indicators(
    alert: dict[str, Any],
) -> tuple[list[ExtractedIndicator], list[DiscardedCandidate]]:
    """Return unique valid IOCs, structured fields first, and the discarded candidates."""
    extracted: dict[tuple[str, str], ExtractedIndicator] = {}
    discarded: dict[tuple[str, str], DiscardedCandidate] = {}
    for field, value in _candidates(alert):
        try:
            indicator = validate_indicator(value)
        except IndicatorValidationError as exc:
            discarded.setdefault((field, str(exc)), DiscardedCandidate(field=field, reason=str(exc)))
            continue
        extracted.setdefault(
            (indicator.type.value, indicator.value),
            ExtractedIndicator(indicator=indicator, field=field),
        )
    return list(extracted.values()), list(discarded.values())
