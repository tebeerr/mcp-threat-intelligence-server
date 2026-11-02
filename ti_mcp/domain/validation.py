"""Strict IOC typing and validation."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from ti_mcp.domain.models import Indicator, IndicatorType


class IndicatorValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ATTACK_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_NUMERIC_LABEL = re.compile(r"^(?:\d+|0[xX][0-9A-Fa-f]+)$")
_ALERT_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_INTERNAL_TLDS = {
    "arpa", "corp", "home", "internal", "intranet", "lan", "local", "localdomain", "localhost",
}
# Reserved for documentation, so they cannot reveal anything about a real network.
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _is_shareable_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Only IOCs safe to disclose may reach external sources: never lab or LAN addresses."""
    target = getattr(address, "ipv4_mapped", None) or address
    if getattr(address, "scope_id", None) or target.is_multicast:
        return False
    return target.is_global or any(target in network for network in _DOCUMENTATION_NETWORKS)


def _is_domain(value: str) -> bool:
    candidate = value[:-1] if value.endswith(".") else value
    labels = candidate.split(".")
    return (
        len(candidate) <= 253
        and len(labels) >= 2
        and all(_DOMAIN_LABEL.fullmatch(label) for label in labels)
        # A numeric TLD is a mangled IP such as 999.1.1.1 or the 127.1 shorthand.
        and not _NUMERIC_LABEL.fullmatch(labels[-1])
    )


def _is_internal_domain(value: str) -> bool:
    return value.rstrip(".").rsplit(".", 1)[-1].lower() in _INTERNAL_TLDS


def _validate_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise IndicatorValidationError("INVALID_INPUT", "Malformed URL") from exc

    if any(character.isspace() for character in value):
        raise IndicatorValidationError("INVALID_INPUT", "URL must not contain whitespace")
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
        if _is_internal_domain(hostname):
            raise IndicatorValidationError("INVALID_INPUT", "Internal URL targets are not allowed")
    else:
        if not _is_shareable_address(address):
            raise IndicatorValidationError(
                "INVALID_INPUT", "Private and non-global URL targets are not allowed"
            )

    # Credentials were rejected above, so the whole netloc is case-insensitive.
    return urlunsplit(parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()))


def validate_indicator(value: str, max_length: int = 2048) -> Indicator:
    if not isinstance(value, str) or not value or value != value.strip():
        raise IndicatorValidationError("INVALID_INPUT", "Indicator must be a non-empty string")
    if len(value) > max_length:
        raise IndicatorValidationError("INVALID_INPUT", "Indicator exceeds the maximum length")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise IndicatorValidationError("INVALID_INPUT", "Control characters are not allowed")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if not _is_shareable_address(address):
            raise IndicatorValidationError(
                "INVALID_INPUT", "Private and non-global addresses are not allowed"
            )
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
        if _is_internal_domain(value):
            raise IndicatorValidationError("INVALID_INPUT", "Internal domains are not allowed")
        return Indicator(type=IndicatorType.DOMAIN, value=value.rstrip(".").lower())

    raise IndicatorValidationError(
        "INVALID_INPUT", "Indicator format is invalid"
    )


def validate_technique_id(value: str) -> str:
    candidate = value.strip().upper() if isinstance(value, str) else ""
    if not _ATTACK_TECHNIQUE.fullmatch(candidate):
        raise IndicatorValidationError(
            "INVALID_INPUT", "Technique id must look like T1059 or T1059.001"
        )
    return candidate


def validate_alert_id(value: str) -> str:
    if not isinstance(value, str) or not _ALERT_ID.fullmatch(value):
        raise IndicatorValidationError("INVALID_INPUT", "Alert id format is invalid")
    return value
