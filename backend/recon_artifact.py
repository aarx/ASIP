import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile


ARTIFACT_SCHEMA_VERSION = 1


class ReconArtifactError(RuntimeError):
    pass


def scan_recon_artifact_path(data_directory, scan_id):
    """Return the canonical artifact path for one scan, rejecting unsafe IDs."""
    if not isinstance(scan_id, int) or isinstance(scan_id, bool) or scan_id <= 0:
        raise ReconArtifactError("scan_id must be a positive integer")

    data_root = Path(data_directory).resolve()
    artifact_path = (
        data_root / "scans" / f"scan_{scan_id}" / "final_output.csv"
    ).resolve()
    if not artifact_path.is_relative_to(data_root):
        raise ReconArtifactError("scan artifact path escapes the data directory")
    return artifact_path


def get_manifest_path(artifact_path):
    artifact_path = Path(artifact_path)
    return artifact_path.with_name(f"{artifact_path.name}.manifest.json")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def publish_recon_artifact(source_path, artifact_path, scan_id, row_count):
    if not isinstance(scan_id, int) or isinstance(scan_id, bool) or scan_id <= 0:
        raise ReconArtifactError("scan_id must be a positive integer")
    if not isinstance(row_count, int) or isinstance(row_count, bool) or row_count < 0:
        raise ReconArtifactError("row_count must be a non-negative integer")

    source_path = Path(source_path)
    artifact_path = Path(artifact_path)
    manifest_path = get_manifest_path(artifact_path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    artifact_temp = None
    manifest_temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=artifact_path.parent,
            prefix=f".{artifact_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as target, open(source_path, "rb") as source:
            artifact_temp = Path(target.name)
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())

        digest = sha256_file(artifact_temp)
        manifest = {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "scan_id": scan_id,
            "sha256": digest,
            "row_count": row_count,
        }

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=artifact_path.parent,
            prefix=f".{manifest_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as target:
            manifest_temp = Path(target.name)
            json.dump(manifest, target, sort_keys=True)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())

        os.replace(artifact_temp, artifact_path)
        artifact_temp = None
        os.replace(manifest_temp, manifest_path)
        manifest_temp = None
        return manifest
    finally:
        for temporary_path in (artifact_temp, manifest_temp):
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass


def read_validated_recon_artifact(artifact_path, expected_scan_id):
    artifact_path = Path(artifact_path)
    manifest_path = get_manifest_path(artifact_path)

    try:
        with open(manifest_path, encoding="utf-8") as source:
            manifest = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReconArtifactError(
            f"Recon artifact manifest is missing or invalid: {manifest_path}"
        ) from exc

    if not isinstance(manifest, dict):
        raise ReconArtifactError("Recon artifact manifest must be a JSON object")
    if manifest.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
        raise ReconArtifactError("Unsupported recon artifact schema version")

    manifest_scan_id = manifest.get("scan_id")
    if (
        not isinstance(manifest_scan_id, int)
        or isinstance(manifest_scan_id, bool)
        or manifest_scan_id != expected_scan_id
    ):
        raise ReconArtifactError(
            f"Recon artifact belongs to scan {manifest_scan_id}, not scan {expected_scan_id}"
        )

    row_count = manifest.get("row_count")
    if not isinstance(row_count, int) or isinstance(row_count, bool) or row_count < 0:
        raise ReconArtifactError("Recon artifact row_count is invalid")

    expected_hash = manifest.get("sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ReconArtifactError("Recon artifact SHA-256 is invalid")

    try:
        artifact_data = artifact_path.read_bytes()
    except OSError as exc:
        raise ReconArtifactError(
            f"Recon artifact is missing or unreadable: {artifact_path}"
        ) from exc

    actual_hash = hashlib.sha256(artifact_data).hexdigest()
    if actual_hash != expected_hash:
        raise ReconArtifactError("Recon artifact SHA-256 does not match its manifest")

    return manifest, artifact_data


def validate_recon_artifact(artifact_path, expected_scan_id):
    manifest, _ = read_validated_recon_artifact(artifact_path, expected_scan_id)
    return manifest
