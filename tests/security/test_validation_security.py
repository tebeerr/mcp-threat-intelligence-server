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


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.5",
        "192.168.56.10",
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fe80::1%eth0",
        "::ffff:10.0.0.1",
        "dc01.corp.local",
        "wazuh.internal",
        "router.lan",
        "1.0.168.192.in-addr.arpa",
        "http://dc01.corp.local/",
        "http://127.1/",
        "http://0x7f.0.0.1/",
    ],
)
def test_internal_values_cannot_leave_the_machine(value):
    with pytest.raises(IndicatorValidationError) as error:
        validate_indicator(value)

    assert error.value.code == "INVALID_INPUT"
