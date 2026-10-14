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


class Correlation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agreeing_sources: int = Field(ge=0)
    conflicts: list[str] = Field(default_factory=list)


class Risk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: RiskLevel
    rule: str


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


class ToolErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str


class ToolErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ToolErrorDetail
