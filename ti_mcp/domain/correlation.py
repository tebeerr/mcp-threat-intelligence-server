"""Deterministic source-result normalization, deduplication and conflict detection."""

from ti_mcp.domain.models import Correlation, SourceResult, SourceStatus


def correlate(results: list[SourceResult]) -> tuple[list[SourceResult], Correlation]:
    by_source: dict[str, SourceResult] = {}
    for result in results:
        by_source.setdefault(result.name, result)

    unique = [
        result.model_copy(update={"tags": _normalize_tags(result.tags)})
        for result in by_source.values()
    ]
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


def _normalize_tags(tags: list[str]) -> list[str]:
    return sorted({tag.strip().casefold() for tag in tags if tag.strip()})
