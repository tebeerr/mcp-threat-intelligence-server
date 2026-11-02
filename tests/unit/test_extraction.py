from ti_mcp.domain.extraction import extract_indicators
from ti_mcp.domain.models import IndicatorType

from tests.fixtures import LAB_IP, PUBLIC_IP, SHA256, SYSMON_ALERT


def extracted_values(alert):
    return {item.indicator.value: item for item in extract_indicators(alert)[0]}


def test_sysmon_alert_yields_public_iocs_with_their_origin_field():
    found = extracted_values(SYSMON_ALERT)

    assert found[PUBLIC_IP].field == "data.win.eventdata.destinationIp"
    assert found["c2.threat.example"].indicator.type == IndicatorType.DOMAIN
    assert found[SHA256].field == "data.win.eventdata.hashes"
    assert found["https://threat.example/payload.ps1"].field == "data.win.eventdata.commandLine"


def test_lab_addresses_are_discarded_and_not_echoed():
    found, discarded = extract_indicators(SYSMON_ALERT)
    values = {item.indicator.value for item in found}

    assert LAB_IP not in values
    assert "10.0.0.9" not in values
    assert any(item.field == "data.win.eventdata.sourceIp" for item in discarded)
    assert LAB_IP not in str([item.model_dump() for item in discarded])


def test_agent_and_manager_fields_are_never_read():
    alert = {"agent": {"ip": PUBLIC_IP}, "manager": {"name": "threat.example"}}

    assert extract_indicators(alert) == ([], [])


def test_file_names_in_free_text_are_not_mistaken_for_domains():
    assert "setup.exe" not in extracted_values(SYSMON_ALERT)


def test_duplicates_keep_the_structured_field():
    alert = {"data": {"srcip": PUBLIC_IP}, "full_log": f"connection from {PUBLIC_IP}"}

    found = extract_indicators(alert)[0]

    assert [item.field for item in found] == ["data.srcip"]


def test_syscheck_hash_and_url_with_trailing_punctuation():
    found = extracted_values({
        "syscheck": {"sha256_after": SHA256},
        "full_log": "fetched http://threat.example/a.sh, then exited",
    })

    assert found[SHA256].field == "syscheck.sha256_after"
    assert "http://threat.example/a.sh" in found


def test_malformed_alert_shapes_do_not_raise():
    assert extract_indicators({"data": "text", "syscheck": 3, "full_log": None}) == ([], [])
