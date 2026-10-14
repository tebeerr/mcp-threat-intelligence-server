"""Deterministic source-result deduplication and conflict detection."""

from ti_mcp.domain.models import Correlation, SourceResult, SourceStatus


def correlate(results: list[SourceResult]) -> tuple[list[SourceResult], Correlation]:
    by_source: dict[str, SourceResult] = {}
    for result in results:
        by_source.setdefault(result.name, result)

    unique = list(by_source.values())
    positive = {
        result.name for result in unique
        if result.status == SourceStatus.OK and result.is_malicious is True
    }
    negative = {
        result.name for result in unique
        if result.status == SourceStatus.OK and result.is_malicious is False
    }
    conflicts = sorted(positive | negative) if positive and negative else []
    return unique, Correlation(agreeing_sources=len(positive), conflicts=conflicts)
