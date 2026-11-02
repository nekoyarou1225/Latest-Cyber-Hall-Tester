"""Comprehensive Unit & Regression Test Suite for MK1Ai Productization & AegisLab Desktop Integration.

Covers P0 through P7:
- P0: Non-destructive preservation of existing `/テストツール` Phase 1 & Phase 2A manifest SHA-256.
- P1: CORE Isolation, ONI_MODE single source of truth, Kill Switch Quorum Gate,
      nftables rule order & IP fragment precedence, PQC vs QKD separation.
- P2: Honeypot Management Engine (dynamic capacity min(license, hw, policy), Outer/Inner,
      start/stop/isolate/auto-recovery, signed backup & restore).
- P3: OS Image Catalog & 7-step preflight switcher (custom OS Ed25519 verification,
      fail-closed rollback on hardware/license mismatch).
- P4: 4-tier License & Entitlement Engine & Ed25519 Offline License Engine
      (device binding, monotonic anti-rollback counter, CORE safety never disabled).
- P5: Developer Group Administration (RBAC, quota overrides, license issue/revoke,
      rejection of client self-declared admin).
- P6: Tester Dedicated Streaming Engine (14 states, whitelisted canvas, <16 age compliance,
      Stream Key non-exposure, Test Mode vs Live Mode separation, SafetyGuard halt)
      & SafeReadOnlyFilesEngine (path traversal, symlink, FIFO special file rejection, full SHA-256).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import mk1ai_productization  # Sets up sys.path for `/テストツール`
from aegislab.core.rollback_verifier import RollbackVerifier
from aegislab.core.safety_guard import SafetyGuard
from aegislab.evidence.recorder import EvidenceRecorder
from aegislab.privacy.redactor import RedactionEngine
from mk1ai_productization.core_isolation import (
    CoreIsolationController,
    CryptoAndBaselineAuditRegistry,
    EvidenceClassification,
    KillSwitchApprovalError,
    NftablesAndFragmentVerifier,
    OniModeState,
)
from mk1ai_productization.honeypot_engine import (
    HoneypotCapacityError,
    HoneypotLayer,
    HoneypotManagementEngine,
    HoneypotState,
    OSImageVerificationError,
)
from mk1ai_productization.license_engine import (
    DeveloperGroupAdminEngine,
    Ed25519OfflineAuthority,
    LicenseValidationError,
    OfflineLicenseEngine,
    PlanTier,
    PrivilegeEscalationBlockedError,
)
from mk1ai_productization.safe_files_engine import (
    FileAccessSecurityError,
    SafeReadOnlyFilesEngine,
)
from mk1ai_productization.streaming_tester import (
    StreamExecutionMode,
    StreamSecurityViolationError,
    StreamState,
    TesterStreamingEngine,
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
TEST_TOOL_DIR = WORKSPACE_ROOT / "テストツール"


class TestMK1AiProductizationSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.recorder = EvidenceRecorder(max_log_entries=512, max_total_log_bytes=256 * 1024)
        self.redactor = RedactionEngine()
        self.safety_guard = SafetyGuard(workspace_dir=TEST_TOOL_DIR)
        self.authority = Ed25519OfflineAuthority()
        self.device_fp = "dev-mk1ai-node-alpha-001"
        self.license_engine = OfflineLicenseEngine(
            public_key_pem=self.authority.public_key_pem,
            local_device_fingerprint=self.device_fp,
            recorder=self.recorder,
        )
        self.dev_admin = DeveloperGroupAdminEngine(
            authority=self.authority,
            license_engine=self.license_engine,
            recorder=self.recorder,
        )
        self.admin_token = "mk1ai-root-founder-token-v1"

    def tearDown(self) -> None:
        self.authority.cleanup()

    # ------------------------------------------------------------------
    # P0: Non-Destructive Preservation of Existing `/テストツール`
    # ------------------------------------------------------------------
    def test_p0_existing_phase1_and_phase2a_sha256_preserved(self) -> None:
        manifest_path = TEST_TOOL_DIR / "phase2a_file_manifest.json"
        self.assertTrue(manifest_path.is_file(), "phase2a_file_manifest.json must exist")
        expected_manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        verifier = RollbackVerifier(workspace_root=TEST_TOOL_DIR)
        report = verifier.verify_manifest_and_workspace(
            manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest_sha,
        )
        self.assertTrue(report["manifest_sha256_verified"])
        self.assertEqual(report["missing_registered_files"], [])
        intact_phase1 = [
            d for d in report["decisions"] if d["status"] == "PROTECTED_PHASE1_INTACT"
        ]
        self.assertEqual(len(intact_phase1), 14)

    # ------------------------------------------------------------------
    # P1: CORE Isolation, Kill Switch Quorum, nftables & PQC/QKD Audit
    # ------------------------------------------------------------------
    def test_p1_kill_switch_requires_per_event_quorum_and_prevents_replay(self) -> None:
        ctrl = CoreIsolationController(
            recorder=self.recorder,
            safety_guard=self.safety_guard,
            quorum_required=2,
        )
        self.assertEqual(ctrl.oni_mode, OniModeState.NORMAL)
        self.assertTrue(ctrl.core_isolation_active)

        # Zero approvals -> rejected
        with self.assertRaises(KillSwitchApprovalError):
            ctrl.execute_kill_switch(event_id="evt-1001", reason="Intrusion", approvals=[])

        # Only 1 approval -> rejected (quorum=2)
        r1 = ctrl.create_admin_approval(event_id="evt-1001", admin_id="admin-alice", now_epoch=1000.0)
        with self.assertRaises(KillSwitchApprovalError):
            ctrl.execute_kill_switch(
                event_id="evt-1001",
                reason="Intrusion",
                approvals=[r1],
                now_epoch=1010.0,
            )

        # 2 distinct valid approvals for same event_id -> executed
        r2 = ctrl.create_admin_approval(event_id="evt-1001", admin_id="admin-bob", now_epoch=1000.0)
        res = ctrl.execute_kill_switch(
            event_id="evt-1001",
            reason="Confirmed outer-to-inner lateral movement",
            approvals=[r1, r2],
            now_epoch=1010.0,
        )
        self.assertTrue(res["executed"])
        self.assertEqual(ctrl.oni_mode, OniModeState.EMERGENCY_QUARANTINE)

        # Replay with same event_id -> rejected
        with self.assertRaises(KillSwitchApprovalError):
            ctrl.execute_kill_switch(
                event_id="evt-1001",
                reason="Replay attempt",
                approvals=[r1, r2],
                now_epoch=1015.0,
            )

    def test_p1_nftables_fragment_order_and_pqc_qkd_separation(self) -> None:
        nft_report = NftablesAndFragmentVerifier.verify_ruleset_specification()
        self.assertTrue(nft_report["default_policies_fail_closed"])
        self.assertTrue(nft_report["rule_order_strictly_monotonic"])
        self.assertTrue(nft_report["ip_fragment_drop_precedes_accept"])
        self.assertEqual(
            nft_report["static_specification_verdict"],
            EvidenceClassification.STATICALLY_VERIFIED.value,
        )
        self.assertEqual(
            nft_report["live_kernel_nft_apply_verdict"],
            EvidenceClassification.NOT_TESTED.value,
        )

        audit = CryptoAndBaselineAuditRegistry.get_remediation_and_crypto_audit()
        qkd = audit["crypto_primitives_and_qkd_separation"]["qkd_hardware"]
        self.assertEqual(qkd["status"], EvidenceClassification.NOT_TESTED.value)
        self.assertEqual(qkd["connection_state"], "NOT_CONNECTED")
        self.assertIn("REG-04", audit["baseline_report_audit"]["regression_items"])
        self.assertIn("REG-06", audit["baseline_report_audit"]["regression_items"])

    # ------------------------------------------------------------------
    # P4 & P5: Offline License Engine, Anti-Rollback, DevGroup & CORE Guarantee
    # ------------------------------------------------------------------
    def test_p4_p5_license_tiers_anti_rollback_and_core_never_stops(self) -> None:
        # 1. Client self-declared admin is strictly blocked
        with self.assertRaises(PrivilegeEscalationBlockedError):
            self.dev_admin.create_group(
                client_self_declared_admin=True,
                group_id="grp-hack",
                group_name="Fake Admin Group",
            )

        # 2. Authorized Developer Group creation & license issuance
        self.dev_admin.create_group(
            authority_token=self.admin_token,
            group_id="grp-sec-ops",
            group_name="MK1Ai Security Engineering Group",
            plan_tier=PlanTier.PRO,
            max_honeypots_quota=32,
            max_bandwidth_mbps_quota=10_000,
        )
        self.dev_admin.add_member(
            authority_token=self.admin_token,
            group_id="grp-sec-ops",
            user_id="alice@mk1ai.internal",
            role="LEAD_ARCHITECT",
        )

        token_seq10 = self.dev_admin.issue_signed_offline_license(
            authority_token=self.admin_token,
            group_id="grp-sec-ops",
            license_id="lic-pro-010",
            device_fingerprint=self.device_fp,
            monotonic_seq=10,
            ttl_sec=3600.0,
            now_epoch=2000.0,
        )

        state = self.license_engine.verify_and_activate_offline_license(token_seq10, now_epoch=2100.0)
        self.assertEqual(state["active_tier"], "PRO")
        self.assertEqual(state["entitlements"]["max_honeypots_by_license"], 32)
        self.assertTrue(state["core_safety_guarantees"]["core_isolation_active"])

        # 3. Anti-rollback: older sequence number (seq=9) with valid signature is rejected!
        token_seq9 = self.dev_admin.issue_signed_offline_license(
            authority_token=self.admin_token,
            group_id="grp-sec-ops",
            license_id="lic-pro-009",
            device_fingerprint=self.device_fp,
            monotonic_seq=9,
            ttl_sec=7200.0,
            now_epoch=2000.0,
        )
        with self.assertRaises(LicenseValidationError):
            self.license_engine.verify_and_activate_offline_license(token_seq9, now_epoch=2100.0)

        # 4. Tampered payload with original signature is rejected
        tampered = dict(token_seq10)
        tampered["plan_tier"] = "ENTERPRISE"
        tampered["monotonic_seq"] = 11
        with self.assertRaises(LicenseValidationError):
            self.license_engine.verify_and_activate_offline_license(tampered, now_epoch=2100.0)

        # 5. Expiration & revocation degrade paid tier to BASIC but NEVER stop CORE safety
        expired_state = self.license_engine.get_current_entitlement_state(now_epoch=99999.0)
        self.assertEqual(expired_state["active_tier"], "BASIC")
        self.assertEqual(expired_state["entitlements"]["max_honeypots_by_license"], 2)
        self.assertTrue(expired_state["core_safety_guarantees"]["core_isolation_active"])
        self.assertTrue(expired_state["core_safety_guarantees"]["emergency_kill_switch_active"])
        self.assertTrue(expired_state["core_safety_guarantees"]["never_disabled_on_license_error"])

    # ------------------------------------------------------------------
    # P2 & P3: Honeypot Management Engine, Dynamic Scaling (>8 nodes),
    #          7-Step OS Switcher & Signed Backup/Restore
    # ------------------------------------------------------------------
    def test_p2_p3_honeypot_dynamic_scaling_os_switch_and_backup(self) -> None:
        hp = HoneypotManagementEngine(
            license_engine=self.license_engine,
            authority=self.authority,
            safety_guard=self.safety_guard,
            recorder=self.recorder,
            admin_policy_max_honeypots=20,
            simulated_host_available_ram_mib=2048,  # (2048-200)//32 = 57 HW limit
            simulated_host_disk_free_mib=4096,
        )

        # Initially on BASIC tier -> effective max = min(2, 57, 20) = 2
        cap_basic = hp.compute_effective_capacity()
        self.assertEqual(cap_basic["effective_max_honeypots"], 2)

        hp.create_honeypot(node_id="hp-outer-1", name="Outer Trap 1", layer=HoneypotLayer.OUTER)
        hp.create_honeypot(node_id="hp-inner-1", name="Inner Vault 1", layer=HoneypotLayer.INNER)

        # 3rd honeypot blocked on BASIC plan
        with self.assertRaises(HoneypotCapacityError):
            hp.create_honeypot(node_id="hp-extra", name="Blocked on Basic")

        # Upgrade to ENTERPRISE group license with quota=16 -> effective max = min(16, 57, 20) = 16 (>8!)
        self.dev_admin.create_group(
            authority_token=self.admin_token,
            group_id="grp-ent",
            group_name="Enterprise Defense",
            plan_tier=PlanTier.ENTERPRISE,
            max_honeypots_quota=16,
            max_bandwidth_mbps_quota=100_000,
        )
        ent_token = self.dev_admin.issue_signed_offline_license(
            authority_token=self.admin_token,
            group_id="grp-ent",
            license_id="lic-ent-100",
            device_fingerprint=self.device_fp,
            monotonic_seq=20,
            now_epoch=3000.0,
        )
        self.license_engine.verify_and_activate_offline_license(ent_token, now_epoch=3010.0)

        cap_ent = hp.compute_effective_capacity()
        self.assertEqual(cap_ent["effective_max_honeypots"], 16)

        # Create 10 total honeypots (proving no hardcoded 8-node limitation!)
        for idx in range(3, 11):
            hp.create_honeypot(
                node_id=f"hp-node-{idx}",
                name=f"Dynamic Node {idx}",
                layer=HoneypotLayer.OUTER if idx % 2 == 0 else HoneypotLayer.INNER,
                os_id="alpine-minimal-3.20",
            )
        self.assertEqual(hp.compute_effective_capacity()["current_total_honeypots"], 10)

        # Individual lifecycle: start -> isolate -> auto-recover -> stop
        hp.start_node("hp-outer-1")
        outer1 = next(n for n in hp.snapshot()["nodes"] if n["node_id"] == "hp-outer-1")
        self.assertEqual(outer1["state"], HoneypotState.RUNNING.value)
        hp.isolate_node("hp-outer-1", "Detected lateral scan")
        hp.trigger_auto_recovery("hp-outer-1")
        hp.stop_node("hp-outer-1")

        # 7-step OS switch to valid Debian 13 minimal succeeds
        sw = hp.switch_node_os_7step("hp-outer-1", "debian-13-minimal", new_ram_mib=64, new_storage_mib=128)
        self.assertTrue(sw["switched"])
        self.assertEqual(sw["current_os"], "debian-13-minimal")

        # 7-step OS switch to Windows Server Guest fails closed & rolls back to debian-13-minimal
        with self.assertRaises(OSImageVerificationError):
            hp.switch_node_os_7step("hp-outer-1", "windows-server-2022-guest", new_ram_mib=4096, new_storage_mib=20480)
        node_after_rollback = next(n for n in hp.snapshot()["nodes"] if n["node_id"] == "hp-outer-1")
        self.assertEqual(node_after_rollback["os_id"], "debian-13-minimal")

        # Register verified custom OS image with Ed25519 signature
        img_bytes = b"custom-initramfs-cpio-gz-payload"
        img_sha = hashlib.sha256(img_bytes).hexdigest()
        sig_payload = f"custom-sec-os-1|custom-verified|2.1.0|x86_64|{img_sha}".encode("utf-8")
        sig_hex = self.authority.sign_payload_bytes(sig_payload)
        desc = hp.register_custom_os_image(
            os_id="custom-sec-os-1",
            display_name="Custom Hardened Linux",
            version="2.1.0",
            architecture="x86_64",
            min_ram_mib=32,
            min_storage_mib=64,
            image_bytes=img_bytes,
            expected_sha256=img_sha,
            signature_ed25519=sig_hex,
        )
        self.assertTrue(desc.signature_verified)

        # Signed backup & restore verification
        backup_bundle = hp.export_signed_backup()
        hp.remove_honeypot("hp-node-10")
        self.assertEqual(hp.compute_effective_capacity()["current_total_honeypots"], 9)
        hp.restore_signed_backup(backup_bundle)
        self.assertEqual(hp.compute_effective_capacity()["current_total_honeypots"], 10)

    # ------------------------------------------------------------------
    # P6: Tester Streaming Engine & Safe Read-Only Files Engine
    # ------------------------------------------------------------------
    def test_p6_tester_streaming_isolation_age_policy_and_secret_protection(self) -> None:
        stream = TesterStreamingEngine(
            safety_guard=self.safety_guard,
            redactor=self.redactor,
            recorder=self.recorder,
        )
        self.assertEqual(stream.state, StreamState.DISCONNECTED)

        # Prohibited canvas source (e.g. full_desktop_capture or aegis_files_content) is rejected
        with self.assertRaises(StreamSecurityViolationError):
            stream.configure_canvas_sources(["tester_summary_metrics", "aegis_files_content"])

        # Under-16 standalone streaming is blocked -> NOT_ELIGIBLE
        st_under16 = stream.verify_age_and_channel_eligibility(
            user_age=15,
            adult_present_in_broadcast=False,
        )
        self.assertEqual(st_under16, StreamState.NOT_ELIGIBLE)

        # Eligible adult (or supervised) restores eligibility
        stream.verify_age_and_channel_eligibility(user_age=22, channel_live_enabled=True)

        # Test Signal runs in TEST_MODE_SIMULATED and never transitions to LIVE
        stream.start_test_signal()
        self.assertEqual(stream.state, StreamState.TESTING)
        with self.assertRaises(StreamSecurityViolationError):
            stream.transition_to_live()
        stream.stop_test_signal()
        self.assertEqual(stream.state, StreamState.STOPPED)

        # Switch to LIVE_YOUTUBE_API mode, connect OAuth with CSRF verification, verify Stream Key is hidden
        stream.set_mode(StreamExecutionMode.LIVE_YOUTUBE_API)
        with self.assertRaises(StreamSecurityViolationError):
            stream.connect_oauth(provided_csrf_state="wrong-csrf", access_token="ya29.valid_token_12345")

        stream.connect_oauth(
            provided_csrf_state=stream.csrf_state_token,
            access_token="ya29.secret_oauth_token_abcdef",
            stream_key="live_987654321_secretkey",
        )
        snap = stream.snapshot()
        snap_str = str(snap)
        self.assertNotIn("ya29.secret_oauth_token_abcdef", snap_str)
        self.assertNotIn("live_987654321_secretkey", snap_str)
        self.assertFalse(snap["stream_key_exposed_to_ui"])

        # Cannot go LIVE when YouTube stream status is only 'ready' (not 'active')
        stream.start_preview("Tester Output Frame #1")
        stream.prepare_youtube_broadcast_and_stream(youtube_stream_active=False)
        with self.assertRaises(StreamSecurityViolationError):
            stream.transition_to_live()

        # Once YouTube confirms 'active', transition to LIVE succeeds
        stream.prepare_youtube_broadcast_and_stream(youtube_stream_active=True)
        self.assertEqual(stream.transition_to_live(), StreamState.LIVE)

        # SafetyGuard RAM breach immediately halts stream
        halted = stream.enforce_safety_guard_during_stream(simulated_available_ram_mib=120)
        self.assertEqual(halted, StreamState.ERROR)

    def test_p6_safe_readonly_files_blocks_traversal_symlinks_and_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sub = root / "docs"
            sub.mkdir()
            reg_file = sub / "readme.txt"
            reg_file.write_bytes(b"AegisLab Verified Read-Only Content\n")

            # Create a FIFO special file and a symlink
            fifo_path = sub / "test_pipe.fifo"
            os.mkfifo(fifo_path)
            symlink_path = sub / "link_outside.txt"
            os.symlink("/etc/passwd", symlink_path)

            engine = SafeReadOnlyFilesEngine(root_dir=root)

            # Listing skips FIFO and symlinks automatically
            listed = engine.list_workspace_files(folder_filter="docs")
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["path"], "docs/readme.txt")

            # Path traversal rejected
            with self.assertRaises(FileAccessSecurityError):
                engine.inspect_regular_file("../etc/passwd")

            # Symlink rejected
            with self.assertRaises(FileAccessSecurityError):
                engine.inspect_regular_file("docs/link_outside.txt")

            # FIFO special file rejected without blocking
            with self.assertRaises(FileAccessSecurityError):
                engine.inspect_regular_file("docs/test_pipe.fifo")

            # Regular file returns exact full-file SHA-256
            info = engine.inspect_regular_file("docs/readme.txt")
            expected_sha = hashlib.sha256(b"AegisLab Verified Read-Only Content\n").hexdigest()
            self.assertEqual(info["full_file_sha256"], expected_sha)
            self.assertEqual(info["hashed_bytes"], info["size_bytes"])


if __name__ == "__main__":
    unittest.main()
