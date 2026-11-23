"""Contract tests for the offline license verifier.

Every test calls the public functions exported by the lic package and not
the private implementation module.  The suite contains exactly fifteen
tests: ten defects plus five end-to-end behaviors.
"""

import base64
import hashlib
import hmac
import json

import pytest

from lic import (
    check_binding,
    check_expiry,
    decode_license,
    grant_features,
    license_batch,
    machine_fingerprint,
    validate_policy,
    verify_signature,
)


NOW = 1_801_296_000
KEY = b"gsb-license-verify-test-key-2026"
FP_A = "a" * 64
FP_B = "b" * 64


def _payload(
    license_id="lic-main",
    *,
    fingerprints=(FP_A,),
    max_permutations=1,
    not_before=NOW - 3600,
    not_after=NOW + 3600,
    features=("audit",),
):
    return {
        "license_id": license_id,
        "machine": {
            "fingerprints": list(fingerprints),
            "max_permutations": max_permutations,
        },
        "not_before": not_before,
        "not_after": not_after,
        "features": list(features),
    }


def _canonical(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _text(body):
    return base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii")


def _signature(body):
    return hmac.new(KEY, body, hashlib.sha256).hexdigest()


def _record(payload, fingerprint=FP_A, *, text=None, signature=None):
    body = _canonical(payload)
    return {
        "license_id": payload["license_id"],
        "text": _text(body) if text is None else text,
        "signature": _signature(body) if signature is None else signature,
        "fingerprint": fingerprint,
    }


def _policy(**overrides):
    policy = {
        "key": KEY,
        "known_features": ["audit", "report"],
        "skew": 30,
        "max_validity_seconds": 31 * 24 * 60 * 60,
    }
    policy.update(overrides)
    return policy


def test_defect_01_fingerprint_is_order_independent():
    sources = {
        "hostname": "ws-alpha",
        "system_uuid": "11111111-2222-3333-4444-555555555555",
        "network_adapters": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
        "volume_ids": ["vol-system", "vol-data"],
    }
    reversed_sources = {name: sources[name] for name in reversed(tuple(sources))}
    reordered_values = {
        "hostname": sources["hostname"],
        "system_uuid": sources["system_uuid"],
        "network_adapters": list(reversed(sources["network_adapters"])),
        "volume_ids": list(reversed(sources["volume_ids"])),
    }

    fingerprint = machine_fingerprint(sources)

    assert machine_fingerprint(reversed_sources) == fingerprint
    assert machine_fingerprint(reordered_values) == fingerprint
    assert len(fingerprint) == 64
    assert set(fingerprint) <= set("0123456789abcdef")


def test_defect_02_fingerprint_covers_network_and_volume():
    sources = {
        "hostname": "ws-alpha",
        "system_uuid": "11111111-2222-3333-4444-555555555555",
        "network_adapters": ["aa:bb:cc:dd:ee:01"],
        "volume_ids": ["vol-system"],
    }
    changed_network = dict(sources)
    changed_network["network_adapters"] = ["aa:bb:cc:dd:ee:99"]
    changed_volume = dict(sources)
    changed_volume["volume_ids"] = ["vol-replacement"]

    fingerprint = machine_fingerprint(sources)

    assert machine_fingerprint(changed_network) != fingerprint
    assert machine_fingerprint(changed_volume) != fingerprint


def test_defect_03_signature_checked_on_raw_body_before_decode():
    body = _canonical(_payload("lic-raw"))
    signature = _signature(body)

    assert verify_signature(body, signature, KEY) is True
    assert verify_signature(body.replace(b",", b", "), signature, KEY) is False

    malformed = b"{not-json"
    bad_signature_record = {
        "license_id": "lic-bad-signature-first",
        "text": _text(malformed),
        "signature": "0" * 64,
        "fingerprint": FP_A,
    }
    bad_json_record = {
        "license_id": "lic-bad-json",
        "text": _text(malformed),
        "signature": _signature(malformed),
        "fingerprint": FP_A,
    }

    results = license_batch(
        [bad_signature_record, bad_json_record],
        _policy(),
        NOW,
    )

    assert results["lic-bad-signature-first"]["reason"] == "bad_signature"
    assert results["lic-bad-json"]["reason"] == "bad_license"


def test_defect_04_signature_uses_constant_time_compare(monkeypatch):
    calls = []
    real_compare_digest = hmac.compare_digest

    def spy(left, right):
        calls.append((left, right))
        return real_compare_digest(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    body = _canonical(_payload("lic-compare"))

    assert verify_signature(body, _signature(body), KEY) is True
    assert calls


def test_defect_05_expiry_checks_start_and_end():
    payload = _payload("lic-window", not_before=1000, not_after=2000)

    assert check_expiry(payload, 1000, 0) is True
    assert check_expiry(payload, 2000, 0) is True
    assert check_expiry(payload, 999, 0) is False
    assert check_expiry(payload, 2001, 0) is False


def test_defect_06_clock_skew_not_doubled():
    payload = _payload("lic-skew", not_before=1000, not_after=2000)

    assert check_expiry(payload, 2030, 30) is True
    assert check_expiry(payload, 2031, 30) is False
    assert check_expiry(payload, 970, 30) is True
    assert check_expiry(payload, 969, 30) is False
    with pytest.raises(ValueError):
        check_expiry(payload, 1500, 301)


def test_defect_07_binding_compares_full_fingerprint():
    shared_prefix = "c" * 63
    authorized = shared_prefix + "0"
    lookalike = shared_prefix + "1"
    single = {
        "machine": {
            "fingerprints": [authorized],
            "max_permutations": 0,
        }
    }
    alternate = {
        "machine": {
            "fingerprints": [authorized, lookalike],
            "max_permutations": 1,
        }
    }

    assert check_binding(single, authorized) is True
    assert check_binding(single, lookalike) is False
    assert check_binding(alternate, lookalike) is True


def test_defect_08_unknown_features_rejected():
    payload = _payload("lic-features", features=("audit", "root"))

    with pytest.raises(ValueError, match="unknown feature"):
        grant_features(payload, ["audit", "report"])

    known = _payload("lic-known", features=("report", "audit"))
    assert grant_features(known, ["audit", "report"]) == ["audit", "report"]


def test_defect_09_policy_rejects_overlong_validity():
    one_year = 366 * 24 * 60 * 60
    issues = validate_policy(_policy(max_validity_seconds=10 * one_year))

    assert "validity_too_long" in issues
    assert validate_policy(_policy()) == []

    overlong = _payload(
        "lic-long",
        not_before=NOW - 100,
        not_after=NOW + 10 * one_year,
    )
    results = license_batch([_record(overlong)], _policy(), NOW)

    assert results["lic-long"]["valid"] is False
    assert results["lic-long"]["reason"] == "policy_validity"


def test_defect_10_batch_does_not_reuse_fingerprint():
    first = _record(_payload("lic-first"), FP_A)
    second = _record(_payload("lic-second"), FP_B)

    results = license_batch([first, second], _policy(), NOW)

    assert results["lic-first"]["valid"] is True
    assert results["lic-second"]["valid"] is False
    assert results["lic-second"]["reason"] == "machine_mismatch"


def test_valid_license_is_accepted():
    results = license_batch(
        [_record(_payload("lic-valid", features=("audit",)))],
        _policy(),
        NOW,
    )

    assert results["lic-valid"] == {
        "valid": True,
        "reason": None,
        "features": ["audit"],
    }


def test_valid_license_rejected_on_another_machine():
    results = license_batch(
        [_record(_payload("lic-moved"), FP_B)],
        _policy(),
        NOW,
    )

    assert results["lic-moved"]["valid"] is False
    assert results["lic-moved"]["reason"] == "machine_mismatch"
    assert results["lic-moved"]["features"] == []


def test_expired_license_is_rejected():
    expired = _payload(
        "lic-expired",
        not_before=NOW - 7200,
        not_after=NOW - 1,
    )
    results = license_batch(
        [_record(expired)],
        _policy(skew=0),
        NOW,
    )

    assert results["lic-expired"]["valid"] is False
    assert results["lic-expired"]["reason"] == "expired"


def test_tampered_license_is_rejected():
    original = _payload("lic-tampered")
    tampered = _payload("lic-tampered", features=("root",))
    record = _record(
        tampered,
        FP_A,
        signature=_signature(_canonical(original)),
    )

    results = license_batch([record], _policy(), NOW)

    assert results["lic-tampered"]["valid"] is False
    assert results["lic-tampered"]["reason"] == "bad_signature"
    assert results["lic-tampered"]["features"] == []


def test_batch_matches_individual_validation():
    good = _record(_payload("lic-batch-good"), FP_A)
    wrong_machine = _record(_payload("lic-batch-wrong"), FP_B)
    policy = _policy()

    together = license_batch([good, wrong_machine], policy, NOW)
    reverse_order = license_batch([wrong_machine, good], policy, NOW)
    individually = {
        **license_batch([good], policy, NOW),
        **license_batch([wrong_machine], policy, NOW),
    }

    assert together == reverse_order
    assert together == individually
