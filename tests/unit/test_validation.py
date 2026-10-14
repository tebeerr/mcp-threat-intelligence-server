import pytest

from ti_mcp.domain.models import IndicatorType
from ti_mcp.domain.validation import IndicatorValidationError, validate_indicator


@pytest.mark.parametrize(
    ("value", "expected_type", "expected_value"),
    [
        ("203.0.113.10", IndicatorType.IPV4, "203.0.113.10"),
        ("2001:db8::1", IndicatorType.IPV6, "2001:db8::1"),
        ("Example.COM", IndicatorType.DOMAIN, "example.com"),
        ("https://example.com/path", IndicatorType.URL, "https://example.com/path"),
        ("A" * 64, IndicatorType.SHA256, "a" * 64),
    ],
)
def test_supported_indicators_are_typed_and_normalized(value, expected_type, expected_value):
    indicator = validate_indicator(value)

    assert indicator.type == expected_type
    assert indicator.value == expected_value


@pytest.mark.parametrize(
    "value", ["", " example.com", "*.example.com", "ftp://example.com", "not an IOC!"]
)
def test_invalid_indicators_are_rejected(value):
    with pytest.raises(IndicatorValidationError):
        validate_indicator(value)


@pytest.mark.parametrize("value", ["CVE-2026-1234", "T1059", "T1059.001"])
def test_valid_but_unimplemented_reference_types_are_unsupported(value):
    with pytest.raises(IndicatorValidationError) as error:
        validate_indicator(value)

    assert error.value.code == "UNSUPPORTED_TYPE"
