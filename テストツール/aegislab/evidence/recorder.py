"""Telemetry & Evidence Manager (Module 19).

Enforces:
- All 16 required evidence fields per test execution.
- SHA-256 hash-chained audit log with strict entry count and byte size caps
  to prevent unbounded memory/disk growth.
- Mandatory Fail-Closed redaction before generating any public/shareable bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from aegislab.core.value_types import Verdict
from aegislab.privacy.redactor import RedactionEngine


class AuditLogCapacityError(RuntimeError):
    """Raised when audit log capacity is exceeded or logging fails."""


REQUIRED_16_EVIDENCE_KEYS: tuple[str, ...] = (
    "test_id",
    "timestamps",
    "target_program_version",
    "os_and_image_version",
    "vm_configuration",
    "environment_info",
    "test_scenario",
    "config_parameters",
    "random_seed",
    "input_data_hash",
    "target_values",
    "measured_values",
    "audit_logs",
    "verdict",
    "reproduction_conditions",
    "unverified_items",
)


@dataclass(frozen=True)
class ChainedAuditEntry:
    seq: int
    event_type: str
    message: str
    prev_sha256: str
    entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "event_type": self.event_type,
            "message": self.message,
            "prev_sha256": self.prev_sha256,
            "entry_sha256": self.entry_sha256,
        }


class EvidenceRecorder:
    """Records hash-chained audit logs and 16-field evidence bundles with size caps."""

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        *,
        max_log_entries: int = 256,
        max_total_log_bytes: int = 128 * 1024,
    ) -> None:
        self._max_log_entries = max_log_entries
        self._max_total_log_bytes = max_total_log_bytes
        self._entries: list[ChainedAuditEntry] = []
        self._total_bytes: int = 0

    @property
    def entries(self) -> tuple[ChainedAuditEntry, ...]:
        return tuple(self._entries)

    def append_log(self, event_type: str, message: str) -> ChainedAuditEntry:
        """Append a hash-chained audit entry; halt if log cap is exceeded."""
        if len(self._entries) >= self._max_log_entries:
            raise AuditLogCapacityError(
                f"Audit log entry cap ({self._max_log_entries}) exceeded; halting safely"
            )
        prev_hash = (
            self._entries[-1].entry_sha256 if self._entries else self.GENESIS_HASH
        )
        seq = len(self._entries) + 1
        canonical = f"{seq}|{event_type}|{message}|{prev_hash}".encode("utf-8")
        if self._total_bytes + len(canonical) > self._max_total_log_bytes:
            raise AuditLogCapacityError(
                f"Audit log byte limit ({self._max_total_log_bytes} B) exceeded; halting safely"
            )
        digest = hashlib.sha256(canonical).hexdigest()
        entry = ChainedAuditEntry(
            seq=seq,
            event_type=event_type,
            message=message,
            prev_sha256=prev_hash,
            entry_sha256=digest,
        )
        self._entries.append(entry)
        self._total_bytes += len(canonical)
        return entry

    def verify_chain_integrity(self) -> bool:
        prev = self.GENESIS_HASH
        for idx, item in enumerate(self._entries, start=1):
            if item.seq != idx or item.prev_sha256 != prev:
                return False
            canonical = f"{item.seq}|{item.event_type}|{item.message}|{item.prev_sha256}".encode("utf-8")
            if hashlib.sha256(canonical).hexdigest() != item.entry_sha256:
                return False
            prev = item.entry_sha256
        return True

    def build_evidence_bundle(
        self,
        *,
        test_id: str,
        started_at: str,
        ended_at: str,
        target_program_version: str,
        os_and_image_version: dict[str, Any],
        vm_configuration: dict[str, Any],
        environment_info: dict[str, Any],
        test_scenario: dict[str, Any],
        config_parameters: dict[str, Any],
        random_seed: str,
        input_data_bytes: bytes,
        target_values: dict[str, Any],
        measured_values: dict[str, Any],
        verdict: Verdict,
        reproduction_conditions: dict[str, Any],
        unverified_items: list[str],
    ) -> dict[str, Any]:
        """Construct a 16-field evidence bundle and validate completeness."""
        if not unverified_items:
            raise ValueError(
                "unverified_items must explicitly list unverified/untested items in Phase 2A"
            )
        if not self.verify_chain_integrity():
            raise RuntimeError("Audit log hash chain integrity check failed")

        input_hash = hashlib.sha256(input_data_bytes).hexdigest()
        bundle: dict[str, Any] = {
            "test_id": test_id,
            "timestamps": {
                "started_at": started_at,
                "ended_at": ended_at,
            },
            "target_program_version": target_program_version,
            "os_and_image_version": os_and_image_version,
            "vm_configuration": vm_configuration,
            "environment_info": environment_info,
            "test_scenario": test_scenario,
            "config_parameters": config_parameters,
            "random_seed": random_seed,
            "input_data_hash": f"sha256:{input_hash}",
            "target_values": target_values,
            "measured_values": measured_values,
            "audit_logs": [e.to_dict() for e in self._entries],
            "verdict": verdict.value,
            "reproduction_conditions": reproduction_conditions,
            "unverified_items": list(unverified_items),
        }

        missing = [k for k in REQUIRED_16_EVIDENCE_KEYS if k not in bundle]
        if missing:
            raise ValueError(f"Missing required evidence keys: {missing}")
        return bundle

    def export_public_bundle(
        self,
        bundle: dict[str, Any],
        redactor: RedactionEngine,
    ) -> dict[str, Any]:
        """Export a sanitized public evidence bundle; Fail-Closed if redaction fails."""
        redacted = redactor.redact_structure(bundle)
        # Ensure JSON serializability after redaction
        serialized = json.dumps(redacted, ensure_ascii=False, sort_keys=True)
        return json.loads(serialized)
