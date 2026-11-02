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


def test_every_rule_explains_itself():
    for results in ([result("a", malicious=True), result("b", malicious=True)], [result("a")]):
        risk, _ = assess_risk(*correlate(results))
        assert risk.explanation


def test_source_without_verdict_never_yields_low_risk():
    no_verdict = result("urlhaus").model_copy(update={"is_malicious": None})

    risk, uncertainty = assess_risk(*correlate([no_verdict]))

    assert risk.rule == "R4"
    assert uncertainty.level == "elevated"


def test_correlation_normalizes_tags():
    tagged = result("otx").model_copy(update={"tags": ["Botnet", " botnet ", "C2", ""]})

    unique, _ = correlate([tagged])

    assert unique[0].tags == ["botnet", "c2"]
