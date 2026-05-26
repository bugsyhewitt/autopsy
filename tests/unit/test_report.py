"""Fast unit tests for the report/finding serialization. angr-free."""

import json

from autopsy.report import Finding, TaintPoint, Report


def test_taintpoint_serializes_address_as_hex():
    tp = TaintPoint(0x401136, "tainted input read")
    d = tp.to_dict()
    assert d == {"address": "0x401136", "description": "tainted input read"}


def test_finding_has_required_contract_fields():
    f = Finding(
        cwe=119,
        function="store_at",
        address=0x401140,
        evidence="scaled-index write",
        taint_trace=[TaintPoint(0x401120, "index from atoi")],
    )
    d = f.to_dict()
    # v0.1 contract: cwe, function, address, taint_trace (array), evidence.
    assert d["cwe"] == 119
    assert d["function"] == "store_at"
    assert d["address"] == "0x401140"
    assert isinstance(d["taint_trace"], list)
    assert d["taint_trace"][0]["address"] == "0x401120"
    assert d["evidence"] == "scaled-index write"


def test_report_json_roundtrips_and_counts():
    rep = Report(binary="b", checks=[78], max_states=1000)
    rep.findings = [
        Finding(cwe=78, function="run_cmd", address=0x40117a, evidence="system()"),
    ]
    parsed = json.loads(rep.to_json())
    assert parsed["binary"] == "b"
    assert parsed["checks"] == [78]
    assert parsed["max_states"] == 1000
    assert parsed["finding_count"] == 1
    assert parsed["findings"][0]["cwe"] == 78
    assert parsed["state_limit_exceeded"] is False


def test_report_state_limit_flag_serializes():
    rep = Report(binary="b", checks=[119], max_states=10, state_limit_exceeded=True,
                 error="state limit exceeded (>10 states)")
    parsed = json.loads(rep.to_json())
    assert parsed["state_limit_exceeded"] is True
    assert "state limit exceeded" in parsed["error"]
