from datetime import datetime, timezone

import pytest

from ti_mcp.domain.correlation import correlate
from ti_mcp.domain.models import ErrorCode, SourceResult, SourceStatus
from ti_mcp.domain.risk import assess_risk


def result(name, status=SourceStatus.OK, malicious=False, error_code=None):
    return SourceResult(
        name=name,
        status=status,
        retrieved_at=datetime.now(timezone.utc),
        is_malicious=malicious if status == SourceStatus.OK else None,
        error_code=error_code,
    )


@pytest.mark.parametrize(
    ("results", "expected_level", "expected_rule"),
    [
        ([result("a", malicious=True), result("b", malicious=True)], "high", "R1"),
        ([result("a", malicious=True)], "medium", "R2"),
        ([result("a")], "low", "R3"),
        ([result("a", SourceStatus.ERROR, error_code=ErrorCode.SOURCE_TIMEOUT)], "indeterminate", "R4"),
    ],
)
def test_risk_rules(results, expected_level, expected_rule):
    unique, correlation = correlate(results)

    risk, _ = assess_risk(unique, correlation)

    assert risk.level.value == expected_level
    assert risk.rule == expected_rule


def test_correlation_deduplicates_sources_and_detects_conflicts():
    unique, correlation = correlate([result("otx", malicious=True), result("otx", malicious=False)])

    assert len(unique) == 1
    assert correlation.agreeing_sources == 1
    assert correlation.conflicts == []


def test_independent_sources_with_opposing_verdicts_create_uncertainty():
    unique, correlation = correlate([result("otx", malicious=True), result("urlhaus")])

    risk, uncertainty = assess_risk(unique, correlation)

    assert correlation.conflicts == ["otx", "urlhaus"]
    assert risk.rule == "R2"
    assert uncertainty.level == "elevated"
