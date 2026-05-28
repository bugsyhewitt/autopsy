"""Fast unit tests for the build-resilient baseline (finding suppression).

angr-free: exercises autopsy.baseline directly with plain Finding objects.
"""

import json

import pytest

from autopsy import baseline
from autopsy.report import Finding


def _f(cwe=119, function="store_at", address=0x401000, evidence="oob write"):
    return Finding(cwe=cwe, function=function, address=address, evidence=evidence)


# --- fingerprint stability ------------------------------------------------


def test_fingerprint_is_deterministic():
    a = baseline.fingerprint(_f())
    b = baseline.fingerprint(_f())
    assert a == b
    assert len(a) == 16
    assert all(c in "0123456789abcdef" for c in a)


def test_fingerprint_ignores_address():
    # The whole point: address shifts on recompile but the fingerprint must not.
    near = baseline.fingerprint(_f(address=0x401000))
    far = baseline.fingerprint(_f(address=0x55aa0000))
    assert near == far


def test_fingerprint_distinguishes_cwe():
    assert baseline.fingerprint(_f(cwe=119)) != baseline.fingerprint(_f(cwe=787))


def test_fingerprint_distinguishes_function():
    assert baseline.fingerprint(_f(function="a")) != baseline.fingerprint(_f(function="b"))


def test_fingerprint_distinguishes_evidence():
    assert baseline.fingerprint(_f(evidence="x")) != baseline.fingerprint(_f(evidence="y"))


# --- build_baseline / serialization ---------------------------------------


def test_build_baseline_shape_and_fields():
    doc = baseline.build_baseline([_f()], binary="/bin/app")
    assert doc["version"] == baseline.BASELINE_VERSION
    assert doc["binary"] == "/bin/app"
    assert len(doc["findings"]) == 1
    entry = doc["findings"][0]
    assert entry["cwe"] == 119
    assert entry["function"] == "store_at"
    assert entry["evidence"] == "oob write"
    assert entry["fingerprint"] == baseline.fingerprint(_f())


def test_build_baseline_dedupes_identical_findings():
    doc = baseline.build_baseline([_f(), _f(), _f()])
    assert len(doc["findings"]) == 1


def test_build_baseline_is_deterministic_sorted():
    # Two distinct findings produced in different orders yield the same doc.
    f1 = _f(cwe=119, evidence="aaa")
    f2 = _f(cwe=787, evidence="bbb")
    d1 = baseline.build_baseline([f1, f2])
    d2 = baseline.build_baseline([f2, f1])
    assert d1["findings"] == d2["findings"]


def test_baseline_json_roundtrips():
    text = baseline.baseline_json([_f()], binary="b")
    fps = baseline.load_fingerprints(text)
    assert fps == {baseline.fingerprint(_f())}


# --- load_fingerprints tolerance ------------------------------------------


def test_load_fingerprints_from_structured_doc():
    text = baseline.baseline_json([_f(cwe=119), _f(cwe=787)])
    fps = baseline.load_fingerprints(text)
    assert fps == {baseline.fingerprint(_f(cwe=119)), baseline.fingerprint(_f(cwe=787))}


def test_load_fingerprints_from_bare_array():
    fps = baseline.load_fingerprints(json.dumps(["abc123", "def456"]))
    assert fps == {"abc123", "def456"}


def test_load_fingerprints_from_string_entries_in_findings():
    doc = {"version": "1", "findings": ["aaa", "bbb"]}
    assert baseline.load_fingerprints(json.dumps(doc)) == {"aaa", "bbb"}


def test_load_fingerprints_rejects_garbage():
    with pytest.raises(ValueError):
        baseline.load_fingerprints("not json{{{")


def test_load_fingerprints_rejects_wrong_shape():
    with pytest.raises(ValueError):
        baseline.load_fingerprints(json.dumps(42))


def test_load_fingerprints_empty_doc():
    assert baseline.load_fingerprints(json.dumps({"version": "1", "findings": []})) == set()


# --- apply_baseline -------------------------------------------------------


def test_apply_baseline_suppresses_matching():
    findings = [_f(cwe=119), _f(cwe=787)]
    accepted = {baseline.fingerprint(_f(cwe=119))}
    kept, n = baseline.apply_baseline(findings, accepted)
    assert n == 1
    assert len(kept) == 1
    assert kept[0].cwe == 787


def test_apply_baseline_keeps_order():
    findings = [_f(cwe=78, evidence="a"), _f(cwe=119, evidence="b"), _f(cwe=787, evidence="c")]
    # Suppress the middle one.
    accepted = {baseline.fingerprint(_f(cwe=119, evidence="b"))}
    kept, n = baseline.apply_baseline(findings, accepted)
    assert n == 1
    assert [k.cwe for k in kept] == [78, 787]


def test_apply_baseline_empty_accepted_is_noop():
    findings = [_f(), _f(cwe=787)]
    kept, n = baseline.apply_baseline(findings, set())
    assert n == 0
    assert kept == findings


def test_apply_baseline_suppresses_after_recompile_address_shift():
    # Record a baseline from a "build A", then suppress the same finding in a
    # "build B" where only the address changed — the core suppression promise.
    original = _f(address=0x401000)
    text = baseline.baseline_json([original])
    accepted = baseline.load_fingerprints(text)

    recompiled = _f(address=0x4022a0)  # same cwe/function/evidence, new address
    kept, n = baseline.apply_baseline([recompiled], accepted)
    assert n == 1
    assert kept == []
