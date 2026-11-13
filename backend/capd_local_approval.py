#!/usr/bin/python3
"""Signed, single-target local approval for Apache CAPD header checks.

The host issuer is installed root-owned and invoked through a restricted
sudoers rule. The backend receives only an Ed25519-signed, short-lived scope;
it never trusts client usernames, environment variables, or a CLI flag as
approval. This module performs no database or network operations.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from capd_approval_contract import (
    APACHE_CHECK_ID,
    APACHE_CHECK_REVISION,
    CAPD_HTTP_HEADER_VERIFY,
    validate_apache_origin,
)


APPROVER_PATH = Path("/usr/local/libexec/asip-capd-approve")
PRIVATE_KEY_PATH = Path("/etc/asip/capd-approval-ed25519.pem")
PUBLIC_KEY_PATH = Path("/run/secrets/capd-approval-ed25519.pub")
APPROVER_GROUP = "asip-capd-operator"
APPROVAL_TTL = timedelta(seconds=120)
MAX_APPROVAL_BYTES = 8192
SCHEMA = "shadowrecon-capd-local-approval-v1"
PAYLOAD_FIELDS = frozenset({
    "schema", "operation", "check_id", "check_revision", "run_id",
    "source_scan_id", "asset", "method", "max_requests", "operator_uid",
    "operator_name", "issued_at", "expires_at",
})
ASSET_FIELDS = frozenset({"asset_id", "domain", "origin"})


class LocalApprovalError(ValueError):
    """A local approval is missing, untrusted, stale, or out of scope."""


def _utc(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _canonical(payload):
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _safe_root_file(path, *, private=False):
    """Require a root-owned regular file and reject symlinks or writable modes."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LocalApprovalError("trusted approval key is unavailable") from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or (private and (metadata.st_mode & 0o177
                             or not metadata.st_mode & 0o400))):
        raise LocalApprovalError("trusted approval key permissions are unsafe")
    parent = path.parent
    while parent != parent.parent:
        try:
            directory = parent.lstat()
        except OSError as exc:
            raise LocalApprovalError("trusted approval key path is unavailable") from exc
        if (stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != 0 or directory.st_mode & 0o022):
            raise LocalApprovalError("trusted approval key path is not root-protected")
        parent = parent.parent
    return path.read_bytes()


def _verify_protected_installation(executable=None):
    executable = Path(executable or sys.argv[0])
    if executable != APPROVER_PATH:
        raise LocalApprovalError("trusted host approval helper is not installed at its protected path")
    current = executable
    while current != current.parent:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise LocalApprovalError("trusted host approval path is unavailable") from exc
        if (stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022):
            raise LocalApprovalError("trusted host approval path is not root-protected")
        current = current.parent
    if os.geteuid() != 0:
        raise LocalApprovalError("host approval helper must run through its restricted root launcher")
    uid = os.getuid()
    if uid <= 0:
        raise LocalApprovalError("container/root identity is not a CAPD operator identity")
    try:
        operator = pwd.getpwuid(uid)
        group = grp.getgrnam(APPROVER_GROUP)
        memberships = os.getgrouplist(operator.pw_name, operator.pw_gid)
    except (KeyError, OSError) as exc:
        raise LocalApprovalError("dedicated CAPD operator group is not configured") from exc
    if group.gr_gid not in memberships:
        raise LocalApprovalError("local OS identity is not in the CAPD operator group")
    return uid, operator.pw_name


def _read_private_key(path=PRIVATE_KEY_PATH):
    data = _safe_root_file(Path(path), private=True)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError) as exc:
        raise LocalApprovalError("trusted approval signing key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise LocalApprovalError("trusted approval signing key must be Ed25519")
    return key


def _read_public_key(path=PUBLIC_KEY_PATH):
    data = _safe_root_file(Path(path))
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as exc:
        raise LocalApprovalError("trusted approval verification key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise LocalApprovalError("trusted approval verification key must be Ed25519")
    return key


def build_approval_payload(*, run_id, source_scan_id, asset_id, domain, origin,
                           operator_uid, operator_name, now=None):
    now = _utc(now or datetime.now(timezone.utc))
    try:
        parsed_run_id = str(uuid.UUID(str(run_id)))
        source_scan_id = int(source_scan_id)
        asset_id = int(asset_id)
    except (TypeError, ValueError, AttributeError) as exc:
        raise LocalApprovalError("approval requires valid run, scan, and asset IDs") from exc
    if source_scan_id <= 0 or asset_id <= 0 or operator_uid <= 0:
        raise LocalApprovalError("approval IDs and operator identity must be positive")
    canonical_domain = str(domain or "").strip().lower().rstrip(".")
    try:
        canonical_origin = validate_apache_origin(origin, canonical_domain)
    except ValueError as exc:
        raise LocalApprovalError("approval endpoint is not bound to the selected asset") from exc
    return {
        "schema": SCHEMA,
        "operation": CAPD_HTTP_HEADER_VERIFY,
        "check_id": APACHE_CHECK_ID,
        "check_revision": APACHE_CHECK_REVISION,
        "run_id": parsed_run_id,
        "source_scan_id": source_scan_id,
        "asset": {
            "asset_id": asset_id, "domain": canonical_domain,
            "origin": canonical_origin,
        },
        "method": "GET",
        "max_requests": 1,
        "operator_uid": int(operator_uid),
        "operator_name": str(operator_name or "").strip(),
        "issued_at": now.isoformat(),
        "expires_at": (now + APPROVAL_TTL).isoformat(),
    }


def sign_approval(payload, private_key):
    if not isinstance(private_key, Ed25519PrivateKey):
        raise LocalApprovalError("trusted approval signing key is invalid")
    encoded = _canonical(payload)
    signature = private_key.sign(encoded)
    document = {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":"))
    if len(rendered.encode("utf-8")) > MAX_APPROVAL_BYTES:
        raise LocalApprovalError("approval document exceeds size limit")
    return rendered


def verify_approval(document, public_key, *, now=None):
    """Verify signer, expiry, operation, revision, and one-target request budget."""
    if isinstance(document, str):
        document = document.encode("utf-8")
    if not isinstance(document, bytes) or len(document) > MAX_APPROVAL_BYTES:
        raise LocalApprovalError("approval document is missing or too large")
    try:
        envelope = json.loads(document)
        payload = envelope["payload"]
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise LocalApprovalError("approval document is malformed") from exc
    if (not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}
            or not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS):
        raise LocalApprovalError("approval payload fields are invalid")
    if not isinstance(public_key, Ed25519PublicKey):
        raise LocalApprovalError("trusted approval verification key is invalid")
    try:
        public_key.verify(signature, _canonical(payload))
    except InvalidSignature as exc:
        raise LocalApprovalError("approval signature is invalid") from exc
    if (payload["schema"] != SCHEMA
            or payload["operation"] != CAPD_HTTP_HEADER_VERIFY
            or payload["check_id"] != APACHE_CHECK_ID
            or payload["check_revision"] != APACHE_CHECK_REVISION
            or payload["method"] != "GET"
            or type(payload["max_requests"]) is not int
            or payload["max_requests"] != 1
            or not isinstance(payload["asset"], dict)
            or set(payload["asset"]) != ASSET_FIELDS):
        raise LocalApprovalError("approval is outside the Apache header-check scope")
    try:
        issued = datetime.fromisoformat(payload["issued_at"])
        expires = datetime.fromisoformat(payload["expires_at"])
        now = _utc(now or datetime.now(timezone.utc))
        issued, expires = _utc(issued), _utc(expires)
        uuid.UUID(payload["run_id"])
        scan_id = int(payload["source_scan_id"])
        asset_id = int(payload["asset"]["asset_id"])
        operator_uid = int(payload["operator_uid"])
        if (issued > now + timedelta(seconds=5) or now >= expires
                or expires <= issued or expires - issued > APPROVAL_TTL
                or type(payload["source_scan_id"]) is not int
                or type(payload["asset"]["asset_id"]) is not int
                or type(payload["operator_uid"]) is not int
                or scan_id <= 0 or asset_id <= 0 or operator_uid <= 0
                or not str(payload["operator_name"]).strip()):
            raise ValueError
        domain = str(payload["asset"]["domain"]).strip().lower().rstrip(".")
        origin = validate_apache_origin(payload["asset"]["origin"], domain)
        if payload["asset"]["domain"] != domain or payload["asset"]["origin"] != origin:
            raise ValueError
    except (TypeError, ValueError, KeyError) as exc:
        raise LocalApprovalError("approval is expired or contains invalid scope") from exc
    return payload


def approval_matches_target(payload, context, target):
    """Bind a verified approval to exactly one run, asset, and stored origin."""
    if not isinstance(target, dict) or context is None:
        return False
    asset = payload.get("asset", {})
    try:
        evidence = target.get("evidence") or []
        observed = next(
            (row.get("observed_url") for row in evidence
             if isinstance(row, dict)
             and row.get("source") == "domain_technology_observations"
             and str(row.get("technology") or "").lower() == "apache"
             and row.get("evidence_type") == "server_header"
             and row.get("observed_url")),
            None,
        )
        origin = validate_apache_origin(observed, target.get("domain"))
    except (TypeError, ValueError):
        return False
    return bool(
        payload.get("run_id") == context.run_id
        and payload.get("check_id") == context.check_id
        and payload.get("check_revision") == context.check_revision
        and payload.get("source_scan_id") == context.source_scan_id
        and asset.get("asset_id") == target.get("domain_id")
        and asset.get("domain") == str(target.get("domain") or "").strip().lower().rstrip(".")
        and asset.get("origin") == origin
        and payload.get("operation") == CAPD_HTTP_HEADER_VERIFY
        and payload.get("method") == "GET"
        and payload.get("max_requests") == 1
    )


def issue_main(argv=None):
    """Root-installed host issuer; only signs one interactive approval."""
    parser = argparse.ArgumentParser(prog="asip-capd-approve")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scan-id", required=True, type=int)
    parser.add_argument("--asset-id", required=True, type=int)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--origin", required=True)
    args = parser.parse_args(argv)
    try:
        uid, operator_name = _verify_protected_installation()
        origin = validate_apache_origin(args.origin, args.domain)
        print(
            f"Approve one GET to asset {args.asset_id} ({args.domain}) at {origin} "
            f"from inventory scan {args.scan_id}? Type APPROVE {args.asset_id} to continue:",
            file=sys.stderr,
        )
        if not sys.stdin.isatty() or input().strip() != f"APPROVE {args.asset_id}":
            raise LocalApprovalError("operator did not confirm the exact target")
        payload = build_approval_payload(
            run_id=args.run_id, source_scan_id=args.scan_id,
            asset_id=args.asset_id, domain=args.domain, origin=origin,
            operator_uid=uid, operator_name=operator_name,
        )
        print(sign_approval(payload, _read_private_key()))
        return 0
    except (LocalApprovalError, ValueError) as exc:
        print(f"CAPD approval denied: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(issue_main())
