import pytest

from ti_mcp.domain.models import IndicatorType
from ti_mcp.domain.validation import validate_indicator


@pytest.mark.parametrize(
    ("value", "indicator_type"),
    [
        ("198.51.100.4", IndicatorType.IPV4),
        ("2001:db8::5", IndicatorType.IPV6),
        ("threat.example", IndicatorType.DOMAIN),
        ("https://threat.example/payload", IndicatorType.URL),
        ("0123456789abcdef" * 4, IndicatorType.SHA256),
    ],
)
def test_reference_indicator_cases(value, indicator_type):
    assert validate_indicator(value).type == indicator_type
