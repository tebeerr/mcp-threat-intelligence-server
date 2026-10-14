"""Explainable deterministic risk rules R1-R4."""

from ti_mcp.domain.models import Correlation, ErrorCode, Risk, RiskLevel, SourceResult, SourceStatus, Uncertainty


def assess_risk(
    results: list[SourceResult], correlation: Correlation
) -> tuple[Risk, Uncertainty]:
    errors = [result for result in results if result.status == SourceStatus.ERROR]
    reasons: list[str] = []
    if errors:
        reasons.append(f"{len(errors)} source(s) unavailable")
    if correlation.conflicts:
        reasons.append("Sources disagree about the indicator")
    if any(result.error_code == ErrorCode.SOURCE_RATE_LIMITED for result in errors):
        reasons.append("A source rate limit was reached")

    if correlation.agreeing_sources >= 2:
        risk = Risk(level=RiskLevel.HIGH, rule="R1")
    elif correlation.agreeing_sources == 1:
        risk = Risk(level=RiskLevel.MEDIUM, rule="R2")
    elif errors or correlation.conflicts or not results:
        risk = Risk(level=RiskLevel.INDETERMINATE, rule="R4")
    else:
        risk = Risk(level=RiskLevel.LOW, rule="R3")

    uncertainty = Uncertainty(
        level="elevated" if reasons or not results else "low",
        reasons=reasons or (["No source returned usable data"] if not results else []),
    )
    return risk, uncertainty
