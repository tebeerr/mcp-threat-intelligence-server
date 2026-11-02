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

    agreeing = correlation.agreeing_sources
    has_negative_verdict = any(
        result.status == SourceStatus.OK and result.is_malicious is False for result in results
    )
    if agreeing >= 2:
        risk = Risk(
            level=RiskLevel.HIGH,
            rule="R1",
            explanation=f"{agreeing} independent sources report the indicator as malicious",
        )
    elif agreeing == 1:
        risk = Risk(
            level=RiskLevel.MEDIUM,
            rule="R2",
            explanation="Exactly one source reports the indicator as malicious",
        )
    elif errors or not has_negative_verdict:
        risk = Risk(
            level=RiskLevel.INDETERMINATE,
            rule="R4",
            explanation="No malicious report, and not every source could give a verdict",
        )
        if not errors:
            reasons.append("No source returned usable data")
    else:
        risk = Risk(
            level=RiskLevel.LOW,
            rule="R3",
            explanation="All sources answered without a malicious report; "
            "absence from these sources does not prove the indicator is safe",
        )

    return risk, Uncertainty(level="elevated" if reasons else "low", reasons=reasons)
