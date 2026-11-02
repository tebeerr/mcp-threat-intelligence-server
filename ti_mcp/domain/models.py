"""Canonical input and report models."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"


class SourceStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


class ErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    SOURCE_TIMEOUT = "SOURCE_TIMEOUT"
    SOURCE_RATE_LIMITED = "SOURCE_RATE_LIMITED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    ALERT_NOT_FOUND = "ALERT_NOT_FOUND"
    TECHNIQUE_NOT_FOUND = "TECHNIQUE_NOT_FOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class RiskLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INDETERMINATE = "indeterminate"


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)


class SourceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    status: SourceStatus
    source_reference: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    retrieved_at: datetime
    source_confidence: float | None = None
    tags: list[str] = Field(default_factory=list)
    is_malicious: bool | None = None
    error_code: ErrorCode | None = None
    note: str | None = None
    from_cache: bool = False


class Correlation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agreeing_sources: int = Field(ge=0)
    conflicts: list[str] = Field(default_factory=list)


class Risk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: RiskLevel
    rule: str
    explanation: str


class Uncertainty(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str
    reasons: list[str] = Field(default_factory=list)


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    indicator: Indicator
    sources: list[SourceResult]
    correlation: Correlation
    risk: Risk
    uncertainty: Uncertainty
    summary: str
    limits: list[str]


class LookupResult(BaseModel):
    """Per-source facts only: no correlation and no risk judgement."""

    model_config = ConfigDict(extra="forbid")

    status: str
    indicator: Indicator
    sources: list[SourceResult]
    limits: list[str]


class AttackTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    url: str | None = None
    deprecated: bool = False
    revoked: bool = False
    source: str = "mitre_attack_stix"
    data_modified: datetime | None = None
    retrieved_at: datetime


class AlertSummary(BaseModel):
    """Fixed subset of a Wazuh alert; raw logs are never part of it."""

    model_config = ConfigDict(extra="forbid")

    id: str
    timestamp: datetime | None = None
    rule_id: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_name: str | None = None


class AlertList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    retrieved_at: datetime
    count: int = Field(ge=0)
    alerts: list[AlertSummary]


class ExtractedIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    indicator: Indicator
    field: str


class DiscardedCandidate(BaseModel):
    """The rejected value is withheld: it is internal or attacker-controlled."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    reason: str


class AlertIndicatorReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    report: Report


class AlertReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    alert: AlertSummary
    indicators: list[AlertIndicatorReport]
    discarded: list[DiscardedCandidate]
    not_analyzed: int = Field(ge=0)
    techniques: list[AttackTechnique]
    unresolved_techniques: list[str]
    risk: Risk
    summary: str
    limits: list[str]


class ToolErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str


class ToolErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ToolErrorDetail
