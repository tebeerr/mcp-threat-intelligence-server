import pytest

from ti_mcp.domain.validation import IndicatorValidationError, validate_indicator


@pytest.mark.parametrize(
    "value",
    ["http://127.0.0.1/admin", "http://10.0.0.1/", "http://[::1]/", "https://user:pass@example.com/"],
)
def test_private_targets_and_credentials_in_urls_are_rejected(value):
    with pytest.raises(IndicatorValidationError) as error:
        validate_indicator(value)

    assert error.value.code == "INVALID_INPUT"


def test_control_characters_are_rejected():
    with pytest.raises(IndicatorValidationError):
        validate_indicator("example.com\nX-Injected: true")
