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

MAX_SKEW_SECONDS = 300
MAX_VALIDITY_SECONDS = 366 * 24 * 60 * 60


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
    raise NotImplementedError("machine_fingerprint")


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
    raise NotImplementedError("decode_license")


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
    raise NotImplementedError("verify_signature")


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
    raise NotImplementedError("check_expiry")


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
    raise NotImplementedError("check_binding")


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
    raise NotImplementedError("grant_features")


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
    raise NotImplementedError("validate_policy")


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
    raise NotImplementedError("license_batch")
