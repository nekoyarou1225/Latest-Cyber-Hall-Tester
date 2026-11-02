"""P4 & P5: License & Entitlement Engine, Offline License Verifier (with Ed25519 /
Asymmetric Signature Verification, Device Binding & Monotonic Anti-Rollback Counter),
and Developer Group Administration Engine.

Core Security Invariant:
- Expiration, invalid signature, rollback detection, or license revocation NEVER
  disables CORE isolation, basic attack detection, emergency Kill Switch, or
  quarantine maintenance.
- Client-side self-declared admin/enterprise flags are strictly rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from aegislab.evidence.recorder import EvidenceRecorder


class PlanTier(str, Enum):
    BASIC = "BASIC"           # Community / Basic: max 2 honeypots
    STANDARD = "STANDARD"     # Standard: max 8 honeypots
    PRO = "PRO"               # Pro: max 32 honeypots + custom OS
    ENTERPRISE = "ENTERPRISE" # Developer Group / Enterprise: dynamic hardware-safe ceiling


class LicenseValidationError(PermissionError):
    """Raised when an offline license fails cryptographic, device, expiry, or anti-rollback checks."""


class PrivilegeEscalationBlockedError(PermissionError):
    """Raised when a client attempts self-declared privilege elevation without verified authority."""


@dataclass(frozen=True)
class PlanEntitlementSpec:
    tier: PlanTier
    display_name: str
    max_honeypots_by_plan: int  # For ENTERPRISE, represents upper policy cap before HW limit
    max_bandwidth_mbps: int
    core_emergency_bandwidth_mbps: int
    allowed_os_families: tuple[str, ...]
    allow_custom_os_images: bool
    allow_outer_inner_custom_ratio: bool
    allow_advanced_dpi_analytics: bool
    allow_dev_group_admin: bool


PLAN_ENTITLEMENTS: dict[PlanTier, PlanEntitlementSpec] = {
    PlanTier.BASIC: PlanEntitlementSpec(
        tier=PlanTier.BASIC,
        display_name="Community / Basic",
        max_honeypots_by_plan=2,
        max_bandwidth_mbps=100,
        core_emergency_bandwidth_mbps=50,
        allowed_os_families=("mk1ai-secure-linux", "alpine-minimal"),
        allow_custom_os_images=False,
        allow_outer_inner_custom_ratio=False,
        allow_advanced_dpi_analytics=False,
        allow_dev_group_admin=False,
    ),
    PlanTier.STANDARD: PlanEntitlementSpec(
        tier=PlanTier.STANDARD,
        display_name="Standard",
        max_honeypots_by_plan=8,
        max_bandwidth_mbps=1_000,
        core_emergency_bandwidth_mbps=50,
        allowed_os_families=("mk1ai-secure-linux", "alpine-minimal", "debian-minimal"),
        allow_custom_os_images=False,
        allow_outer_inner_custom_ratio=True,
        allow_advanced_dpi_analytics=False,
        allow_dev_group_admin=False,
    ),
    PlanTier.PRO: PlanEntitlementSpec(
        tier=PlanTier.PRO,
        display_name="Pro",
        max_honeypots_by_plan=32,
        max_bandwidth_mbps=10_000,
        core_emergency_bandwidth_mbps=50,
        allowed_os_families=("mk1ai-secure-linux", "alpine-minimal", "debian-minimal", "ubuntu-server-lts", "custom-verified"),
        allow_custom_os_images=True,
        allow_outer_inner_custom_ratio=True,
        allow_advanced_dpi_analytics=True,
        allow_dev_group_admin=False,
    ),
    PlanTier.ENTERPRISE: PlanEntitlementSpec(
        tier=PlanTier.ENTERPRISE,
        display_name="Developer Group / Enterprise",
        max_honeypots_by_plan=256,  # Dynamic ceiling bounded by hardware_safe_limit
        max_bandwidth_mbps=100_000,
        core_emergency_bandwidth_mbps=100,
        allowed_os_families=(
            "mk1ai-secure-linux",
            "alpine-minimal",
            "debian-minimal",
            "ubuntu-server-lts",
            "freebsd-minimal",
            "windows-server-guest",
            "custom-verified",
        ),
        allow_custom_os_images=True,
        allow_outer_inner_custom_ratio=True,
        allow_advanced_dpi_analytics=True,
        allow_dev_group_admin=True,
    ),
}


class Ed25519OfflineAuthority:
    """Offline authority helper using OpenSSL Ed25519 (only public key is stored in the client verifier)."""

    def __init__(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._priv_path = Path(self._tmpdir.name) / "authority_ed25519.pem"
        self._pub_path = Path(self._tmpdir.name) / "authority_ed25519.pub"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self._priv_path)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self._priv_path), "-pubout", "-out", str(self._pub_path)],
            check=True,
            capture_output=True,
        )
        self.public_key_pem: str = self._pub_path.read_text(encoding="utf-8")

    def cleanup(self) -> None:
        self._tmpdir.cleanup()

    def sign_payload_bytes(self, payload: bytes) -> str:
        """Sign canonical bytes with offline authority Ed25519 private key (used only by Issuer/Test Authority)."""
        data_file = Path(self._tmpdir.name) / "payload.bin"
        sig_file = Path(self._tmpdir.name) / "payload.sig"
        data_file.write_bytes(payload)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self._priv_path),
                "-rawin",
                "-in",
                str(data_file),
                "-out",
                str(sig_file),
            ],
            check=True,
            capture_output=True,
        )
        return sig_file.read_bytes().hex()

    @staticmethod
    def verify_with_public_key_pem(public_key_pem: str, payload: bytes, signature_hex: str) -> bool:
        """Verify Ed25519 signature using ONLY the public key PEM."""
        try:
            sig_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        with tempfile.TemporaryDirectory() as td:
            pub_file = Path(td) / "verify.pub"
            data_file = Path(td) / "data.bin"
            sig_file = Path(td) / "data.sig"
            pub_file.write_text(public_key_pem, encoding="utf-8")
            data_file.write_bytes(payload)
            sig_file.write_bytes(sig_bytes)
            res = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(pub_file),
                    "-rawin",
                    "-in",
                    str(data_file),
                    "-sigfile",
                    str(sig_file),
                ],
                capture_output=True,
            )
            return res.returncode == 0


@dataclass
class OfflineLicenseEngine:
    """Air-gap ready offline license verifier using Ed25519 public key, device fingerprint,
    revocation list, and monotonic sequence counter to prevent rollback attacks.
    """

    public_key_pem: str
    local_device_fingerprint: str
    recorder: EvidenceRecorder
    _highest_monotonic_seq: int = 0
    _revoked_license_ids: set[str] = field(default_factory=set)
    _active_license: dict[str, Any] | None = None
    _last_verified_epoch: float | None = None
    _degraded_reason: str = "Default Community/Basic tier active (no external license loaded)"

    @staticmethod
    def canonicalize_license_body(body: dict[str, Any]) -> bytes:
        filtered = {k: v for k, v in body.items() if k != "signature_ed25519"}
        return json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def revoke_license(self, license_id: str, reason: str) -> None:
        self._revoked_license_ids.add(license_id)
        if self._active_license and self._active_license.get("license_id") == license_id:
            self._active_license = None
            self._degraded_reason = f"License '{license_id}' was revoked ({reason}); reverted to Basic tier with CORE safety 100% active."
        self.recorder.append_log("LICENSE_REVOKED", f"Revoked license_id={license_id}: {reason}")

    def verify_and_activate_offline_license(
        self,
        signed_token: dict[str, Any],
        *,
        now_epoch: float | None = None,
    ) -> dict[str, Any]:
        """Verify Ed25519 signature, device binding, expiration, revocation, and monotonic sequence."""
        now = now_epoch if now_epoch is not None else time.time()
        required = {
            "license_id",
            "plan_tier",
            "device_fingerprint",
            "issued_at_epoch",
            "expires_at_epoch",
            "monotonic_seq",
            "signature_ed25519",
        }
        missing = required - set(signed_token.keys())
        if missing:
            self._degraded_reason = f"Missing required license fields: {sorted(missing)}"
            raise LicenseValidationError(self._degraded_reason)

        sig_hex = str(signed_token["signature_ed25519"])
        canonical = self.canonicalize_license_body(signed_token)
        if not Ed25519OfflineAuthority.verify_with_public_key_pem(self.public_key_pem, canonical, sig_hex):
            self._degraded_reason = "Ed25519 signature verification failed (tampered or untrusted issuer); CORE protection remains active"
            self.recorder.append_log("LICENSE_REJECTED_SIGNATURE", self._degraded_reason)
            raise LicenseValidationError(self._degraded_reason)

        lic_id = str(signed_token["license_id"])
        if lic_id in self._revoked_license_ids:
            self._degraded_reason = f"License '{lic_id}' is on the offline revocation list (CRL)"
            self.recorder.append_log("LICENSE_REJECTED_REVOKED", self._degraded_reason)
            raise LicenseValidationError(self._degraded_reason)

        if signed_token["device_fingerprint"] != self.local_device_fingerprint:
            self._degraded_reason = (
                f"Device fingerprint mismatch: token bound to '{signed_token['device_fingerprint']}', "
                f"local is '{self.local_device_fingerprint}'"
            )
            self.recorder.append_log("LICENSE_REJECTED_DEVICE", self._degraded_reason)
            raise LicenseValidationError(self._degraded_reason)

        seq = int(signed_token["monotonic_seq"])
        if seq <= self._highest_monotonic_seq:
            self._degraded_reason = (
                f"Rollback attack blocked: license monotonic_seq ({seq}) <= highest seen ({self._highest_monotonic_seq})"
            )
            self.recorder.append_log("LICENSE_REJECTED_ROLLBACK", self._degraded_reason)
            raise LicenseValidationError(self._degraded_reason)

        if now > float(signed_token["expires_at_epoch"]):
            self._active_license = None
            self._degraded_reason = f"License '{lic_id}' expired; paid extensions disabled while CORE isolation remains 100% active"
            self.recorder.append_log("LICENSE_EXPIRED", self._degraded_reason)
            raise LicenseValidationError(self._degraded_reason)

        tier = PlanTier(signed_token["plan_tier"])
        self._highest_monotonic_seq = seq
        self._active_license = dict(signed_token)
        self._last_verified_epoch = now
        self._degraded_reason = "Verified active offline license"
        self.recorder.append_log(
            "LICENSE_ACTIVATED",
            f"Activated offline license id={lic_id} tier={tier.value} seq={seq}",
        )
        return self.get_current_entitlement_state(now_epoch=now)

    def get_current_entitlement_state(self, *, now_epoch: float | None = None) -> dict[str, Any]:
        """Return effective plan and guarantee that CORE safety controls are NEVER disabled."""
        now = (
            now_epoch
            if now_epoch is not None
            else (self._last_verified_epoch if self._last_verified_epoch is not None else time.time())
        )
        tier = PlanTier.BASIC
        license_valid = False
        custom_cap_honeypots: int | None = None
        custom_cap_bw: int | None = None

        if self._active_license is not None:
            lic_id = self._active_license["license_id"]
            if lic_id in self._revoked_license_ids:
                self._active_license = None
                self._degraded_reason = f"License '{lic_id}' revoked; graceful fallback to BASIC"
            elif now > float(self._active_license["expires_at_epoch"]):
                self._active_license = None
                self._degraded_reason = f"License '{lic_id}' expired; graceful fallback to BASIC"
            else:
                tier = PlanTier(self._active_license["plan_tier"])
                license_valid = True
                custom_cap_honeypots = self._active_license.get("custom_max_honeypots")
                custom_cap_bw = self._active_license.get("custom_max_bandwidth_mbps")

        spec = PLAN_ENTITLEMENTS[tier]
        max_hp = custom_cap_honeypots if custom_cap_honeypots is not None else spec.max_honeypots_by_plan
        max_bw = custom_cap_bw if custom_cap_bw is not None else spec.max_bandwidth_mbps

        return {
            "active_tier": tier.value,
            "display_name": spec.display_name,
            "license_verified": license_valid,
            "highest_monotonic_seq": self._highest_monotonic_seq,
            "status_note": self._degraded_reason,
            "core_safety_guarantees": {
                "core_isolation_active": True,
                "basic_attack_detection_active": True,
                "emergency_kill_switch_active": True,
                "quarantine_maintenance_active": True,
                "core_emergency_bandwidth_mbps": spec.core_emergency_bandwidth_mbps,
                "never_disabled_on_license_error": True,
            },
            "entitlements": {
                "max_honeypots_by_license": max_hp,
                "max_bandwidth_mbps": max_bw,
                "allowed_os_families": list(spec.allowed_os_families),
                "allow_custom_os_images": spec.allow_custom_os_images,
                "allow_outer_inner_custom_ratio": spec.allow_outer_inner_custom_ratio,
                "allow_advanced_dpi_analytics": spec.allow_advanced_dpi_analytics,
                "allow_dev_group_admin": spec.allow_dev_group_admin,
            },
        }


@dataclass
class DeveloperGroupRecord:
    group_id: str
    group_name: str
    plan_tier: PlanTier
    max_honeypots_quota: int
    max_bandwidth_mbps_quota: int
    allowed_os_families: list[str]
    members: dict[str, str] = field(default_factory=dict)  # user_id -> role
    issued_license_ids: list[str] = field(default_factory=list)


class DeveloperGroupAdminEngine:
    """Manages Developer Groups, member RBAC, quota overrides, license issuance/revocation,
    and rejects any client-side self-declared elevation.
    """

    def __init__(
        self,
        *,
        authority: Ed25519OfflineAuthority,
        license_engine: OfflineLicenseEngine,
        recorder: EvidenceRecorder,
    ) -> None:
        self._authority = authority
        self._license_engine = license_engine
        self._recorder = recorder
        self._groups: dict[str, DeveloperGroupRecord] = {}
        self._authority_admin_token_hash = hashlib.sha256(b"mk1ai-root-founder-token-v1").hexdigest()

    def _verify_admin_authority(
        self,
        *,
        authority_token: str | None = None,
        client_self_declared_admin: bool = False,
    ) -> None:
        """Strictly block client self-declared privilege; require cryptographic server authority token."""
        if client_self_declared_admin and not authority_token:
            self._recorder.append_log(
                "SECURITY_VIOLATION_SELF_DECLARED_ADMIN",
                "Blocked client attempt to self-declare Developer Group / Enterprise admin privilege.",
            )
            raise PrivilegeEscalationBlockedError(
                "Client self-declared privilege elevation is strictly prohibited."
            )
        if not authority_token:
            raise PrivilegeEscalationBlockedError("Missing server-verified authority token.")
        candidate_hash = hashlib.sha256(authority_token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(candidate_hash, self._authority_admin_token_hash):
            self._recorder.append_log(
                "SECURITY_VIOLATION_INVALID_ADMIN_TOKEN",
                "Rejected invalid Developer Group authority token.",
            )
            raise PrivilegeEscalationBlockedError("Invalid Developer Group authority token.")

    def create_group(
        self,
        *,
        authority_token: str | None = None,
        client_self_declared_admin: bool = False,
        group_id: str,
        group_name: str,
        plan_tier: PlanTier = PlanTier.ENTERPRISE,
        max_honeypots_quota: int = 64,
        max_bandwidth_mbps_quota: int = 40_000,
        allowed_os_families: list[str] | None = None,
    ) -> dict[str, Any]:
        self._verify_admin_authority(
            authority_token=authority_token,
            client_self_declared_admin=client_self_declared_admin,
        )
        if group_id in self._groups:
            raise ValueError(f"Group '{group_id}' already exists")
        spec = PLAN_ENTITLEMENTS[plan_tier]
        rec = DeveloperGroupRecord(
            group_id=group_id,
            group_name=group_name,
            plan_tier=plan_tier,
            max_honeypots_quota=max_honeypots_quota,
            max_bandwidth_mbps_quota=max_bandwidth_mbps_quota,
            allowed_os_families=allowed_os_families or list(spec.allowed_os_families),
        )
        self._groups[group_id] = rec
        self._recorder.append_log(
            "DEV_GROUP_CREATED",
            f"Created Developer Group id={group_id} tier={plan_tier.value} hp_quota={max_honeypots_quota}",
        )
        return self.get_group_summary(group_id)

    def add_member(
        self,
        *,
        authority_token: str,
        group_id: str,
        user_id: str,
        role: str = "SECURITY_ENGINEER",
    ) -> dict[str, Any]:
        self._verify_admin_authority(authority_token=authority_token)
        grp = self._groups[group_id]
        grp.members[user_id] = role
        self._recorder.append_log(
            "DEV_GROUP_MEMBER_ADDED",
            f"Added member={user_id} role={role} to group={group_id}",
        )
        return self.get_group_summary(group_id)

    def remove_member(
        self,
        *,
        authority_token: str,
        group_id: str,
        user_id: str,
    ) -> dict[str, Any]:
        self._verify_admin_authority(authority_token=authority_token)
        grp = self._groups[group_id]
        grp.members.pop(user_id, None)
        self._recorder.append_log(
            "DEV_GROUP_MEMBER_REMOVED",
            f"Removed member={user_id} from group={group_id}",
        )
        return self.get_group_summary(group_id)

    def update_group_policy(
        self,
        *,
        authority_token: str,
        group_id: str,
        plan_tier: PlanTier | None = None,
        max_honeypots_quota: int | None = None,
        max_bandwidth_mbps_quota: int | None = None,
        allowed_os_families: list[str] | None = None,
    ) -> dict[str, Any]:
        self._verify_admin_authority(authority_token=authority_token)
        grp = self._groups[group_id]
        if plan_tier is not None:
            grp.plan_tier = plan_tier
        if max_honeypots_quota is not None:
            if max_honeypots_quota < 1:
                raise ValueError("max_honeypots_quota must be >= 1")
            grp.max_honeypots_quota = max_honeypots_quota
        if max_bandwidth_mbps_quota is not None:
            if max_bandwidth_mbps_quota < 10:
                raise ValueError("max_bandwidth_mbps_quota must be >= 10")
            grp.max_bandwidth_mbps_quota = max_bandwidth_mbps_quota
        if allowed_os_families is not None:
            grp.allowed_os_families = list(allowed_os_families)
        self._recorder.append_log(
            "DEV_GROUP_POLICY_UPDATED",
            f"Updated policy for group={group_id}: tier={grp.plan_tier.value} hp={grp.max_honeypots_quota} bw={grp.max_bandwidth_mbps_quota}",
        )
        return self.get_group_summary(group_id)

    def issue_signed_offline_license(
        self,
        *,
        authority_token: str | None = None,
        client_self_declared_admin: bool = False,
        group_id: str,
        license_id: str,
        device_fingerprint: str,
        monotonic_seq: int,
        ttl_sec: float = 86400.0 * 30,
        now_epoch: float | None = None,
    ) -> dict[str, Any]:
        self._verify_admin_authority(
            authority_token=authority_token,
            client_self_declared_admin=client_self_declared_admin,
        )
        grp = self._groups[group_id]
        now = now_epoch if now_epoch is not None else time.time()
        body: dict[str, Any] = {
            "license_id": license_id,
            "group_id": group_id,
            "plan_tier": grp.plan_tier.value,
            "device_fingerprint": device_fingerprint,
            "issued_at_epoch": now,
            "expires_at_epoch": now + ttl_sec,
            "monotonic_seq": monotonic_seq,
            "custom_max_honeypots": grp.max_honeypots_quota,
            "custom_max_bandwidth_mbps": grp.max_bandwidth_mbps_quota,
            "allowed_os_families": list(grp.allowed_os_families),
        }
        canonical = OfflineLicenseEngine.canonicalize_license_body(body)
        sig_hex = self._authority.sign_payload_bytes(canonical)
        body["signature_ed25519"] = sig_hex
        grp.issued_license_ids.append(license_id)
        self._recorder.append_log(
            "DEV_GROUP_LICENSE_ISSUED",
            f"Issued Ed25519 offline license id={license_id} group={group_id} seq={monotonic_seq}",
        )
        return body

    def revoke_group_license(
        self,
        *,
        authority_token: str,
        license_id: str,
        reason: str,
    ) -> None:
        self._verify_admin_authority(authority_token=authority_token)
        self._license_engine.revoke_license(license_id, reason)

    def get_group_summary(self, group_id: str) -> dict[str, Any]:
        grp = self._groups[group_id]
        return {
            "group_id": grp.group_id,
            "group_name": grp.group_name,
            "plan_tier": grp.plan_tier.value,
            "max_honeypots_quota": grp.max_honeypots_quota,
            "max_bandwidth_mbps_quota": grp.max_bandwidth_mbps_quota,
            "allowed_os_families": list(grp.allowed_os_families),
            "members": dict(grp.members),
            "issued_license_ids": list(grp.issued_license_ids),
        }

    def list_groups(self) -> list[dict[str, Any]]:
        return [self.get_group_summary(gid) for gid in sorted(self._groups.keys())]
