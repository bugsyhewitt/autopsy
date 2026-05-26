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


def test_finding_confidence_defaults_to_medium():
    f = Finding(cwe=78, function="run_cmd", address=0x40117a, evidence="system()")
    assert f.confidence == "medium"
    assert f.to_dict()["confidence"] == "medium"


def test_finding_confidence_is_preserved_and_serialized():
    f = Finding(
        cwe=415,
        function="dbl",
        address=0x401200,
        evidence="double-free",
        confidence="high",
    )
    assert f.confidence == "high"
    assert f.to_dict()["confidence"] == "high"


def test_finding_confidence_in_report_json():
    rep = Report(binary="b", checks=[416], max_states=1000)
    rep.findings = [
        Finding(cwe=416, function="uaf", address=0x4012, evidence="use-after",
                confidence="low"),
    ]
    parsed = json.loads(rep.to_json())
    assert parsed["findings"][0]["confidence"] == "low"


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
