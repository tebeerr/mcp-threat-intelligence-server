"""Strict IOC typing and validation."""

import ipaddress
import re
from urllib.parse import urlsplit

from ti_mcp.domain.models import Indicator, IndicatorType


class IndicatorValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ATTACK_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _is_domain(value: str) -> bool:
    candidate = value[:-1] if value.endswith(".") else value
    labels = candidate.split(".")
    return (
        len(candidate) <= 253
        and len(labels) >= 2
        and all(_DOMAIN_LABEL.fullmatch(label) for label in labels)
    )


def _validate_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise IndicatorValidationError("INVALID_INPUT", "Malformed URL") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise IndicatorValidationError("INVALID_INPUT", "URL must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise IndicatorValidationError("INVALID_INPUT", "URL credentials are not allowed")
    if port is not None and not 1 <= port <= 65535:
        raise IndicatorValidationError("INVALID_INPUT", "Invalid URL port")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if not _is_domain(hostname):
            raise IndicatorValidationError("INVALID_INPUT", "Invalid URL hostname")
    else:
        if not address.is_global:
            raise IndicatorValidationError(
                "INVALID_INPUT", "Private and non-global URL targets are not allowed"
            )

    return value


def validate_indicator(value: str, max_length: int = 2048) -> Indicator:
    if not isinstance(value, str) or not value or value != value.strip():
        raise IndicatorValidationError("INVALID_INPUT", "Indicator must be a non-empty string")
    if len(value) > max_length:
        raise IndicatorValidationError("INVALID_INPUT", "Indicator exceeds the maximum length")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise IndicatorValidationError("INVALID_INPUT", "Control characters are not allowed")
    if "*" in value:
        raise IndicatorValidationError("INVALID_INPUT", "Wildcards are not allowed")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        indicator_type = IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6
        return Indicator(type=indicator_type, value=str(address))

    if _SHA256.fullmatch(value):
        return Indicator(type=IndicatorType.SHA256, value=value.lower())

    if value.lower().startswith(("http://", "https://")):
        return Indicator(type=IndicatorType.URL, value=_validate_url(value))

    if "://" in value:
        raise IndicatorValidationError("INVALID_INPUT", "Only HTTP and HTTPS URLs are allowed")

    if _CVE.fullmatch(value) or _ATTACK_TECHNIQUE.fullmatch(value):
        raise IndicatorValidationError(
            "UNSUPPORTED_TYPE", "Supported types: IPv4, IPv6, domain, URL, SHA-256"
        )

    if _is_domain(value):
        return Indicator(type=IndicatorType.DOMAIN, value=value.rstrip(".").lower())

    raise IndicatorValidationError(
        "INVALID_INPUT", "Indicator format is invalid"
    )
