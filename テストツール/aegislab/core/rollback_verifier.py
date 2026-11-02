"""Hash-Verified Rollback Verifier without `rm -rf` or circular manifest self-reference.

Enforces:
- `phase2a_file_manifest.json` never includes its own entry/hash inside itself.
- Before inspecting entries, the manifest file itself is verified against an externally
  supplied 64-character SHA-256 hash (`expected_manifest_sha256`).
- Rejects unknown files, symlinks, non-regular files, hash/size mismatches,
  and protected Phase 1 files (`preexisting_protected: true`).
- Actual file deletion is strictly locked (`DeletionNotApprovedError`) until separate
  explicit user approval is granted.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any

SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ManifestVerificationError(RuntimeError):
    """Raised when the manifest file is tampered with or invalid."""


class DeletionNotApprovedError(PermissionError):
    """Raised because actual file deletion is prohibited without separate explicit approval."""


@dataclass(frozen=True)
class FileAuditDecision:
    relative_path: str
    eligible_for_phase2a_rollback: bool
    status: str
    reason: str
    recorded_sha256: str | None
    actual_sha256: str | None


def compute_file_sha256(path: Path) -> str:
    """Compute exact 64-character lowercase hex SHA-256 of a regular file."""
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Refusing to hash non-regular file or symlink: {path}")
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    digest = h.hexdigest()
    assert len(digest) == 64
    return digest


class RollbackVerifier:
    """Verifies Phase 2A rollback candidates strictly by SHA-256 without deleting anything."""

    def __init__(self, workspace_root: Path) -> None:
        self._workspace_root = workspace_root.resolve(strict=True)

    def verify_manifest_and_workspace(
        self,
        manifest_path: Path,
        expected_manifest_sha256: str,
    ) -> dict[str, Any]:
        """Verify manifest integrity and classify every file in the workspace."""
        if not SHA256_HEX_PATTERN.fullmatch(expected_manifest_sha256):
            raise ManifestVerificationError(
                "expected_manifest_sha256 must be an exact 64-character lowercase hex string"
            )
        if not manifest_path.exists() or manifest_path.is_symlink():
            raise ManifestVerificationError("Manifest file is missing or is a symlink")

        actual_manifest_sha256 = compute_file_sha256(manifest_path)
        if actual_manifest_sha256 != expected_manifest_sha256:
            raise ManifestVerificationError(
                f"Manifest SHA-256 mismatch: expected {expected_manifest_sha256}, "
                f"got {actual_manifest_sha256}"
            )

        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = payload.get("files", {})
        if not isinstance(entries, dict):
            raise ManifestVerificationError("Manifest 'files' section must be a JSON object")

        manifest_rel = str(manifest_path.resolve().relative_to(self._workspace_root))
        if manifest_rel in entries:
            raise ManifestVerificationError(
                "Circular self-reference detected: manifest must not include its own entry"
            )

        decisions: list[FileAuditDecision] = []
        observed_rel_paths: set[str] = set()

        for p in sorted(self._workspace_root.rglob("*")):
            rel = str(p.relative_to(self._workspace_root))
            if rel == manifest_rel:
                continue
            lst = p.lstat()
            if stat.S_ISLNK(lst.st_mode):
                observed_rel_paths.add(rel)
                decisions.append(
                    FileAuditDecision(
                        relative_path=rel,
                        eligible_for_phase2a_rollback=False,
                        status="REJECTED_SYMLINK",
                        reason="Symlinks are strictly rejected for rollback operations",
                        recorded_sha256=None,
                        actual_sha256=None,
                    )
                )
                continue
            if stat.S_ISDIR(lst.st_mode):
                continue
            observed_rel_paths.add(rel)
            if not stat.S_ISREG(lst.st_mode):
                decisions.append(
                    FileAuditDecision(
                        relative_path=rel,
                        eligible_for_phase2a_rollback=False,
                        status="REJECTED_SPECIAL_FILE",
                        reason="Non-regular special file rejected",
                        recorded_sha256=None,
                        actual_sha256=None,
                    )
                )
                continue

            actual_sha = compute_file_sha256(p)
            if rel not in entries:
                decisions.append(
                    FileAuditDecision(
                        relative_path=rel,
                        eligible_for_phase2a_rollback=False,
                        status="REJECTED_UNKNOWN_FILE",
                        reason="File is not registered in phase2a_file_manifest.json",
                        recorded_sha256=None,
                        actual_sha256=actual_sha,
                    )
                )
                continue

            meta = entries[rel]
            rec_sha = meta.get("sha256")
            rec_size = meta.get("size_bytes")
            protected = bool(meta.get("preexisting_protected", False))
            owner_phase = meta.get("owner_phase")

            if protected:
                status = (
                    "PROTECTED_PHASE1_INTACT"
                    if actual_sha == rec_sha and lst.st_size == rec_size
                    else "PROTECTED_PHASE1_TAMPERED_ERROR"
                )
                decisions.append(
                    FileAuditDecision(
                        relative_path=rel,
                        eligible_for_phase2a_rollback=False,
                        status=status,
                        reason="Pre-existing Phase 1 file is permanently protected from deletion",
                        recorded_sha256=rec_sha,
                        actual_sha256=actual_sha,
                    )
                )
                continue

            if owner_phase != "PHASE_2A":
                decisions.append(
                    FileAuditDecision(
                        relative_path=rel,
                        eligible_for_phase2a_rollback=False,
                        status="REJECTED_OWNER_PHASE_MISMATCH",
                        reason=f"owner_phase is {owner_phase!r}, expected 'PHASE_2A'",
                        recorded_sha256=rec_sha,
                        actual_sha256=actual_sha,
                    )
                )
                continue

            if actual_sha != rec_sha or lst.st_size != rec_size:
                decisions.append(
                    FileAuditDecision(
                        relative_path=rel,
                        eligible_for_phase2a_rollback=False,
                        status="REJECTED_HASH_OR_SIZE_MISMATCH",
                        reason="File content or size differs from creation-time SHA-256 record",
                        recorded_sha256=rec_sha,
                        actual_sha256=actual_sha,
                    )
                )
                continue

            decisions.append(
                FileAuditDecision(
                    relative_path=rel,
                    eligible_for_phase2a_rollback=True,
                    status="VERIFIED_PHASE2A_CANDIDATE",
                    reason="Exact creation-time SHA-256 and PHASE_2A ownership verified (dry-run only)",
                    recorded_sha256=rec_sha,
                    actual_sha256=actual_sha,
                )
            )

        missing_files = sorted(set(entries.keys()) - observed_rel_paths)
        return {
            "manifest_sha256_verified": True,
            "manifest_sha256": actual_manifest_sha256,
            "missing_registered_files": missing_files,
            "decisions": [d.__dict__ for d in decisions],
            "deletion_policy": "LOCKED_PROHIBITED_WITHOUT_SEPARATE_USER_APPROVAL",
        }

    def execute_deletion(self, *args: Any, **kwargs: Any) -> None:
        """Deletion is unconditionally blocked until separate explicit user approval."""
        raise DeletionNotApprovedError(
            "File deletion is strictly prohibited without separate explicit user approval."
        )
