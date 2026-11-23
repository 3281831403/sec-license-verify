"""Core license-verification contracts and unimplemented stubs.

The public facade lives in lic/api.py and re-exports the eight functions
below.  This module is the only implementation file in the repository.

Canonical license body
----------------------
A license body is a UTF-8 JSON object.  Canonical serialization uses
json.dumps with sort_keys=True, separators=(",", ":"), ensure_ascii=False,
and no trailing newline.  License text is the unpadded URL-safe base64
encoding of those exact bytes.  A signature is HMAC-SHA256(key, raw body
bytes) rendered as 64 lowercase hexadecimal characters.  There is zero
normalization tolerance: whitespace, key order, escapes, and duplicate
keys are all significant at the signature boundary.

Required payload fields
-----------------------
license_id: non-empty str
machine: object with fingerprints and max_permutations
not_before: int Unix seconds, inclusive
not_after: int Unix seconds, inclusive
features: list of feature-name strings

Times are Unix seconds supplied explicitly by the caller.  No wall clock,
randomness, network access, or third-party package is used.
"""

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping

MAX_SKEW_SECONDS = 300
MAX_VALIDITY_SECONDS = 366 * 24 * 60 * 60

_BASE64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_HEX_DIGITS = frozenset("0123456789abcdef")

_REQUIRED_FINGERPRINT_FIELDS = frozenset(
    {"hostname", "system_uuid", "network_adapters", "volume_ids"}
)
_REQUIRED_PAYLOAD_FIELDS = frozenset(
    {"license_id", "machine", "not_before", "not_after", "features"}
)
_REQUIRED_MACHINE_FIELDS = frozenset({"fingerprints", "max_permutations"})
_REQUIRED_RECORD_FIELDS = frozenset(
    {"license_id", "text", "signature", "fingerprint"}
)


def _is_int(value) -> bool:
    """True only for real integers; bool is not an integer time value."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex64(value) -> bool:
    """True only for a complete 64-character lowercase hexadecimal value."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX_DIGITS for character in value)
    )


def _normalize_identifiers(values, field) -> list:
    """Return sorted, de-duplicated non-empty strings for a device field."""
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError(f"{field} must be an iterable of non-empty strings")
    try:
        items = list(values)
    except TypeError as exc:
        raise ValueError(
            f"{field} must be an iterable of non-empty strings"
        ) from exc
    if not items:
        raise ValueError(f"{field} must not be empty")
    for item in items:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{field} must contain non-empty strings")
    return sorted(set(items))


def _reject_duplicate_keys(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(name):
    raise ValueError(f"invalid JSON constant: {name}")


def _text_to_body(text) -> bytes:
    """Strictly decode unpadded URL-safe base64 text to its raw bytes."""
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    if any(character not in _BASE64_ALPHABET for character in text):
        raise ValueError("text is not unpadded URL-safe base64")
    if len(text) % 4 == 1:
        raise ValueError("text has an impossible base64 length")
    padded = text + "=" * ((-len(text)) % 4)
    try:
        body = base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True
        )
    except ValueError as exc:
        raise ValueError("text is not valid base64") from exc
    if base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii") != text:
        raise ValueError("text is not canonical URL-safe base64")
    return body


def _body_to_payload(body) -> dict:
    """Parse raw body bytes into a structurally valid payload dictionary."""
    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("body is not valid UTF-8") from exc
    try:
        payload = json.loads(
            body_text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except ValueError as exc:
        raise ValueError("body is not a valid JSON document") from exc
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    if set(payload.keys()) != _REQUIRED_PAYLOAD_FIELDS:
        raise ValueError("payload has missing or unknown fields")

    license_id = payload["license_id"]
    if not isinstance(license_id, str) or not license_id:
        raise ValueError("license_id must be a non-empty string")

    machine = payload["machine"]
    if not isinstance(machine, dict):
        raise ValueError("machine must be an object")
    if not _REQUIRED_MACHINE_FIELDS <= set(machine.keys()):
        raise ValueError("machine is missing required fields")
    fingerprints = machine["fingerprints"]
    if not isinstance(fingerprints, list):
        raise ValueError("machine fingerprints must be a list")
    for fingerprint in fingerprints:
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError("machine fingerprints must be non-empty strings")
    if not _is_int(machine["max_permutations"]):
        raise ValueError("max_permutations must be an integer")

    if not _is_int(payload["not_before"]):
        raise ValueError("not_before must be an integer")
    if not _is_int(payload["not_after"]):
        raise ValueError("not_after must be an integer")

    features = payload["features"]
    if not isinstance(features, list):
        raise ValueError("features must be a list")
    for feature in features:
        if not isinstance(feature, str) or not feature:
            raise ValueError("features must contain non-empty strings")

    return payload


def _valid_feature_registry(known_features) -> bool:
    if not isinstance(known_features, list):
        return False
    for feature in known_features:
        if not isinstance(feature, str) or not feature:
            return False
    return len(set(known_features)) == len(known_features)


def _invalid(reason) -> dict:
    return {"valid": False, "reason": reason, "features": []}


def _validate_record(record, key, known_features, skew, max_validity, now) -> dict:
    """Validate one batch record without consulting any other record."""
    # 1. Record shape.  A malformed record is reported, not raised: the
    #    batch contract requires one bad record not to abort the batch.
    if not _REQUIRED_RECORD_FIELDS <= set(record.keys()):
        return _invalid("bad_record")
    text = record["text"]
    signature = record["signature"]
    fingerprint = record["fingerprint"]
    if not isinstance(text, str) or not isinstance(signature, str):
        return _invalid("bad_record")
    if not _is_hex64(fingerprint):
        return _invalid("bad_record")

    # 2. Strict base64 decoding of the text, before any parsing.
    try:
        body = _text_to_body(text)
    except ValueError:
        return _invalid("bad_text")

    # 3. Signature over the raw decoded body, before the body is parsed.
    if not verify_signature(body, signature, key):
        return _invalid("bad_signature")

    # 4. Only now may the payload be parsed and trusted.
    try:
        payload = _body_to_payload(body)
    except ValueError:
        return _invalid("bad_license")

    # 5. Binding against this record's own observed fingerprint only.
    try:
        bound = check_binding(payload, fingerprint)
    except ValueError:
        return _invalid("bad_license")
    if not bound:
        return _invalid("machine_mismatch")

    # 6. Policy validity limit applies to the signed window size.
    if payload["not_after"] - payload["not_before"] > max_validity:
        return _invalid("policy_validity")

    # 7. Expiry, with the policy skew applied exactly once at each endpoint.
    try:
        if not check_expiry(payload, now, skew):
            return _invalid("expired")
    except ValueError:
        return _invalid("bad_license")

    # 8. Features come from the registry, never from the body alone.
    try:
        granted = grant_features(payload, known_features)
    except ValueError as exc:
        if str(exc).startswith("unknown feature:"):
            return _invalid("unknown_feature")
        return _invalid("bad_license")
    return {"valid": True, "reason": None, "features": granted}


def machine_fingerprint(sources) -> str:
    """Return a stable machine fingerprint as 64 lowercase hex characters.

    sources must be a mapping with exactly these keys: hostname and
    system_uuid as non-empty strings, plus network_adapters and volume_ids
    as iterables of non-empty strings.  A missing, unknown, or empty field
    is a ValueError.

    The fingerprint includes hostname, system UUID, every network adapter
    identifier, and every volume identifier.  To make it independent of
    dictionary insertion order and device enumeration order, sort field
    names and sort plus de-duplicate the adapter and volume values.  Build
    the canonical JSON described in the module docstring, encode it as
    UTF-8, and return hashlib.sha256(body).hexdigest().

    The fingerprint is evidence for binding, not a secret.
    """
    if not isinstance(sources, Mapping):
        raise ValueError("sources must be a mapping")
    if set(sources.keys()) != _REQUIRED_FINGERPRINT_FIELDS:
        raise ValueError("sources has missing or unknown fields")

    hostname = sources["hostname"]
    system_uuid = sources["system_uuid"]
    if not isinstance(hostname, str) or not hostname:
        raise ValueError("hostname must be a non-empty string")
    if not isinstance(system_uuid, str) or not system_uuid:
        raise ValueError("system_uuid must be a non-empty string")

    body = json.dumps(
        {
            "hostname": hostname,
            "network_adapters": _normalize_identifiers(
                sources["network_adapters"], "network_adapters"
            ),
            "system_uuid": system_uuid,
            "volume_ids": _normalize_identifiers(
                sources["volume_ids"], "volume_ids"
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def decode_license(text) -> dict:
    """Decode license text into its payload dictionary.

    text must be a str containing strict ASCII unpadded URL-safe base64.
    Whitespace, padding, standard-base64 characters, and invalid UTF-8 are
    ValueError.  The decoded bytes must be one UTF-8 JSON object with no
    duplicate object keys.  Duplicate keys are rejected rather than
    silently collapsed because that ambiguity enables signature bypasses.

    The object must contain exactly the five required payload fields listed
    in the module docstring.  Their basic types and non-emptiness are
    checked here; machine binding is checked by check_binding, and time
    ordering is checked by check_expiry.  A missing, extra, or malformed
    field raises ValueError.

    This function parses data and does not verify signatures.  Callers must
    verify the signature over the original decoded body bytes before using
    any value returned here; never decode or trust a body first.
    """
    return _body_to_payload(_text_to_body(text))


def verify_signature(body, signature, key) -> bool:
    """Verify that signature is the exact HMAC-SHA256 of raw body bytes.

    body must be bytes-like and is used byte-for-byte: no parsing,
    canonicalization, whitespace trimming, or re-serialization is allowed.
    key must be non-empty bytes.  signature must be exactly 64 lowercase
    hexadecimal characters; any other shape returns False.

    Compute hmac.new(key, body, hashlib.sha256).hexdigest() and compare it
    with hmac.compare_digest in constant time.  Never use the ordinary
    equality operator for the secret comparison.  Return True only on an
    exact match.  Signature tolerance is zero.
    """
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("body must be bytes-like")
    if not isinstance(key, (bytes, bytearray)) or not len(key):
        raise ValueError("key must be non-empty bytes")
    if not _is_hex64(signature):
        return False
    expected = hmac.new(bytes(key), bytes(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def check_expiry(payload, now, skew) -> bool:
    """Return whether now is inside the signed validity window.

    payload["not_before"] and payload["not_after"] are integer Unix
    seconds, and both endpoints are inclusive.  now is integer Unix
    seconds.  skew is an integer allowance in seconds, from 0 through
    MAX_SKEW_SECONDS inclusive; a larger or negative skew is ValueError.

    A value outside the signed window is tolerated only within skew
    seconds of the nearest endpoint, and the allowance is applied exactly
    once.  The effective acceptance interval is therefore
    not_before - skew through not_after + skew inclusive, never a window
    widened by twice the skew.  With skew equal to 0 the signed endpoints
    are accepted exactly and no extra tolerance exists.  Invalid fields or
    now outside the integer range raise ValueError.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a mapping")
    if "not_before" not in payload or "not_after" not in payload:
        raise ValueError("payload is missing validity fields")
    not_before = payload["not_before"]
    not_after = payload["not_after"]
    if not _is_int(not_before) or not _is_int(not_after):
        raise ValueError("validity bounds must be integers")
    if not _is_int(now):
        raise ValueError("now must be an integer")
    if not _is_int(skew) or skew < 0 or skew > MAX_SKEW_SECONDS:
        raise ValueError("skew must be an integer from 0 through MAX_SKEW_SECONDS")
    if not_before > not_after:
        raise ValueError("not_before must not exceed not_after")
    return not_before - skew <= now <= not_after + skew


def check_binding(payload, fingerprint) -> bool:
    """Return whether fingerprint is fully authorized for this license.

    payload["machine"] must be an object with fingerprints, a non-empty
    list of full 64-character lowercase hexadecimal values, and
    max_permutations, a non-negative integer.  The list may contain at
    most one primary fingerprint plus max_permutations alternate
    fingerprints, so its length must not exceed max_permutations + 1.

    fingerprint must itself be a full 64-character lowercase hexadecimal
    value.  Return True only when it equals one complete authorized value,
    compared with hmac.compare_digest or an equivalent constant-time full
    comparison.  Prefix, suffix, startswith, and truncated comparisons are
    forbidden.  Invalid shapes raise ValueError; a well-formed but
    unauthorized fingerprint returns False.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a mapping")
    if "machine" not in payload:
        raise ValueError("payload is missing machine")
    machine = payload["machine"]
    if not isinstance(machine, Mapping):
        raise ValueError("machine must be an object")
    if not _REQUIRED_MACHINE_FIELDS <= set(machine.keys()):
        raise ValueError("machine is missing required fields")

    authorized = machine["fingerprints"]
    if not isinstance(authorized, list) or not authorized:
        raise ValueError("fingerprints must be a non-empty list")
    for value in authorized:
        if not _is_hex64(value):
            raise ValueError("authorized fingerprints must be 64 hex characters")

    max_permutations = machine["max_permutations"]
    if not _is_int(max_permutations) or max_permutations < 0:
        raise ValueError("max_permutations must be a non-negative integer")
    if len(authorized) > max_permutations + 1:
        raise ValueError("too many authorized fingerprints")

    if not _is_hex64(fingerprint):
        raise ValueError("fingerprint must be 64 lowercase hex characters")

    matched = False
    for value in authorized:
        # Full-length constant-time comparison; never a prefix comparison.
        matched |= hmac.compare_digest(fingerprint, value)
    return bool(matched)


def grant_features(payload, features) -> list:
    """Return the sorted feature names authorized by payload and registry.

    features is the registry of known feature names.  payload["features"]
    must be a list of unique non-empty strings.  Every requested feature
    must be present in the registry.  If any requested feature is unknown,
    raise ValueError("unknown feature: <name>") rather than trusting the
    license body, dropping the feature, or granting it anyway.

    The result is a new list of authorized names in ascending sorted
    order, so callers cannot mutate the payload through the result.
    Invalid registry data or duplicate payload features raise ValueError.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a mapping")
    if "features" not in payload:
        raise ValueError("payload is missing features")
    requested = payload["features"]
    if not isinstance(requested, list):
        raise ValueError("payload features must be a list")
    for feature in requested:
        if not isinstance(feature, str) or not feature:
            raise ValueError("payload features must be non-empty strings")
    if len(set(requested)) != len(requested):
        raise ValueError("payload features must be unique")

    if isinstance(features, (str, bytes, bytearray)):
        raise ValueError("feature registry must be an iterable of names")
    try:
        registry = list(features)
    except TypeError as exc:
        raise ValueError(
            "feature registry must be an iterable of names"
        ) from exc
    for feature in registry:
        if not isinstance(feature, str) or not feature:
            raise ValueError("feature registry must contain non-empty strings")
    if len(set(registry)) != len(registry):
        raise ValueError("feature registry must be unique")

    known = set(registry)
    for feature in requested:
        if feature not in known:
            raise ValueError(f"unknown feature: {feature}")

    return sorted(requested)


def validate_policy(policy) -> list[str]:
    """Return deterministic issue codes for an authorization policy.

    The policy mapping must provide key, known_features,
    max_validity_seconds, and skew.  key is non-empty bytes;
    known_features is a list of unique non-empty strings; skew is an
    integer from 0 through MAX_SKEW_SECONDS; max_validity_seconds is a
    positive integer no greater than MAX_VALIDITY_SECONDS.

    Return an empty list for a valid policy.  Otherwise return each
    applicable code once, in this order:
    key_invalid, known_features_invalid, skew_invalid,
    max_validity_invalid, validity_too_long.
    validity_too_long is required when max_validity_seconds exceeds
    MAX_VALIDITY_SECONDS; long-lived authorization must not be accepted
    silently.

    This validator intentionally does not inspect machine binding and does
    not impose an additional feature allowlist beyond registry shape:
    binding is a per-license runtime check, and feature membership is
    enforced by grant_features.  It does not require an expiry field; it
    validates the policy limits that will be applied to licenses.
    """
    if not isinstance(policy, Mapping):
        raise ValueError("policy must be a mapping")

    issues = []

    key = policy.get("key")
    if not isinstance(key, (bytes, bytearray)) or not len(key):
        issues.append("key_invalid")

    if not _valid_feature_registry(policy.get("known_features")):
        issues.append("known_features_invalid")

    skew = policy.get("skew")
    if not _is_int(skew) or skew < 0 or skew > MAX_SKEW_SECONDS:
        issues.append("skew_invalid")

    max_validity = policy.get("max_validity_seconds")
    if not _is_int(max_validity) or max_validity <= 0:
        issues.append("max_validity_invalid")
    elif max_validity > MAX_VALIDITY_SECONDS:
        issues.append("validity_too_long")

    return issues


def license_batch(licenses, policy, now) -> dict:
    """Validate a sequence of licenses independently and return results.

    Each input record is a mapping with license_id, text, signature, and
    fingerprint.  license_id must be unique.  text and signature are the
    values accepted by decode_license and verify_signature.  fingerprint
    belongs to that record's observed machine and is never shared with or
    copied from another record.

    Return a mapping from license_id to:
    valid result:  {"valid": True, "reason": None, "features": [...]}
    invalid result: {"valid": False, "reason": code, "features": []}

    Each record is processed independently in this security order:
    validate record shape, strict base64 decode, verify the signature over
    the raw decoded body before parsing, decode the payload, check
    binding using only this record's fingerprint, enforce
    policy["max_validity_seconds"] against not_after - not_before, check
    expiry with policy["skew"], then grant features from
    policy["known_features"].

    Failure reason codes are bad_record, bad_text, bad_signature,
    bad_license, machine_mismatch, policy_validity, expired, and
    unknown_feature.  Once a step fails, later steps and later features
    are not trusted.  One invalid record must not abort or influence any
    other record, and batch results must match validating each record
    alone.  Overall malformed arguments, duplicate license_id values, or
    an unusable policy raise ValueError instead of producing results.
    """
    if isinstance(licenses, (str, bytes, bytearray)):
        raise ValueError("licenses must be a sequence of records")
    try:
        records = list(licenses)
    except TypeError as exc:
        raise ValueError("licenses must be a sequence of records") from exc

    if not isinstance(policy, Mapping):
        raise ValueError("policy must be a mapping")
    policy_issues = validate_policy(policy)
    if policy_issues:
        raise ValueError(
            "unusable policy: " + ", ".join(policy_issues)
        )

    if not _is_int(now):
        raise ValueError("now must be an integer")

    license_ids = []
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("each record must be a mapping")
        license_id = record.get("license_id")
        if not isinstance(license_id, str) or not license_id:
            raise ValueError("each record needs a non-empty license_id")
        license_ids.append(license_id)
    if len(set(license_ids)) != len(license_ids):
        raise ValueError("duplicate license_id values")

    key = bytes(policy["key"])
    known_features = policy["known_features"]
    skew = policy["skew"]
    max_validity = policy["max_validity_seconds"]

    results = {}
    for record, license_id in zip(records, license_ids):
        # Each call uses only this record's own fingerprint and fields.
        results[license_id] = _validate_record(
            record, key, known_features, skew, max_validity, now
        )
    return results
