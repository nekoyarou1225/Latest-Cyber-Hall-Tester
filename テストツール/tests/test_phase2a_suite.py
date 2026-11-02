"""Comprehensive Unit & Integration Test Suite for Phase 2A.

All privacy/redaction tests use 100% synthetic RFC-compliant test vectors.
Run with:
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from aegislab.core.config_manager import (
    ConfigManager,
    ImmutableSafetyPolicyError,
    MANDATORY_SAFETY_CONTROLS,
    OPTIONAL_FEATURES,
    PHASE2A_LOCKED_FEATURES,
    Phase2AProhibitedFeatureError,
)
from aegislab.core.rollback_verifier import (
    DeletionNotApprovedError,
    ManifestVerificationError,
    RollbackVerifier,
    compute_file_sha256,
)
from aegislab.core.safety_guard import (
    ProhibitedPhase2AOperationError,
    ResourceLimitExceededError,
    ResourceThresholds,
    SafetyGuard,
)
from aegislab.core.value_types import (
    ControlScope,
    LabeledMetric,
    MAX_COUNT_INT,
    MetricCategory,
    SystemState,
    Verdict,
    parse_exact_decimal_int,
)
from aegislab.evidence.recorder import (
    AuditLogCapacityError,
    EvidenceRecorder,
    REQUIRED_16_EVIDENCE_KEYS,
)
from aegislab.evidence.report_generator import (
    ExaggeratedClaimError,
    ReportGenerator,
)
from aegislab.monitor.device_monitor import DeviceMonitor, SensorStatus
from aegislab.privacy.redactor import (
    REDACTION_LIMITATION_DISCLOSURE,
    RedactionEngine,
    RedactionFailClosedError,
)
from aegislab.sim.bot_simulator import VirtualBotSimulator
from aegislab.sim.packet_counter import CounterInvariantError, PacketCounterEngine
from aegislab.ui.preview_app import PreviewAppController

WORKSPACE_DIR = Path(__file__).resolve().parent.parent


class TestPhase2AConfigAndSafetyLocks(unittest.TestCase):
    """1. Initial OFF policy, orthogonal switches, and scope separation."""

    def test_all_20_optional_features_default_off(self) -> None:
        cfg = ConfigManager()
        opts = cfg.get_all_optional_features()
        self.assertEqual(len(opts), 20)
        for name, state in opts.items():
            self.assertFalse(state, f"Optional feature {name} must default to False")
        self.assertEqual(cfg.default_guest_os, "mk1ai-secure-linux")
        self.assertEqual(cfg.default_guest_os_status, "NOT_BUILT_UNVERIFIED")

    def test_orthogonal_toggle_and_phase2a_locks(self) -> None:
        cfg = ConfigManager(enforce_phase2a_locks=True)
        allowed_features = [
            f for f in OPTIONAL_FEATURES if f not in PHASE2A_LOCKED_FEATURES
        ]
        self.assertGreater(len(allowed_features), 0)

        for target in allowed_features:
            cfg.set_optional_feature(target, True)
            for other, val in cfg.get_all_optional_features().items():
                if other == target:
                    self.assertTrue(val)
                else:
                    self.assertFalse(
                        val, f"Enabling {target} must not enable {other}"
                    )
            cfg.set_optional_feature(target, False)

        for locked in PHASE2A_LOCKED_FEATURES:
            with self.subTest(locked=locked):
                with self.assertRaises(Phase2AProhibitedFeatureError):
                    cfg.set_optional_feature(locked, True)
                self.assertFalse(cfg.get_optional_feature(locked))

    def test_mandatory_controls_immutable_and_scope_separated(self) -> None:
        cfg = ConfigManager()
        mandatory = cfg.get_all_mandatory_controls()
        self.assertEqual(len(mandatory), 11)
        for name in MANDATORY_SAFETY_CONTROLS:
            self.assertTrue(mandatory[name])
            with self.assertRaises(ImmutableSafetyPolicyError):
                cfg.set_mandatory_control(name, False)
            with self.assertRaises(ImmutableSafetyPolicyError):
                cfg.set_optional_feature(name, False)

        statuses = cfg.get_detailed_mandatory_control_statuses()
        for st in statuses:
            self.assertEqual(st.software_scope, ControlScope.APPLICATION_CONFIG_LOCK)
            self.assertEqual(st.os_scope, ControlScope.OS_VIRTUALIZATION_ISOLATION)
            self.assertEqual(st.os_kernel_enforcement_status, Verdict.NOT_TESTED)

    def test_restart_resets_all_optional_features_to_off(self) -> None:
        cfg = ConfigManager(enforce_phase2a_locks=False)
        for name in OPTIONAL_FEATURES:
            cfg.set_optional_feature(name, True)
        cfg.simulate_restart()
        for name, state in cfg.get_all_optional_features().items():
            self.assertFalse(state, f"{name} must reset to False on restart")


class TestPhase2APacketCounterExactPrecision(unittest.TestCase):
    """2. Packet counter (1..10^16) exact precision, IEEE-754 boundary, and invariants."""

    def test_exact_boundary_values_up_to_10_pow_16(self) -> None:
        boundaries = [
            "1",
            "9007199254740991",    # 2^53 - 1 (JS Number.MAX_SAFE_INTEGER)
            "9007199254740992",    # 2^53
            "9007199254740993",    # 2^53 + 1 (loses precision in IEEE-754 float)
            "9999999999999999",    # 10^16 - 1
            "10000000000000000",   # 10^16 (1京)
        ]
        for b_str in boundaries:
            with self.subTest(boundary=b_str):
                eng = PacketCounterEngine(b_str)
                snap0 = eng.snapshot()
                self.assertEqual(snap0.target_packets, b_str)
                self.assertEqual(snap0.remaining_packets, b_str)
                self.assertEqual(snap0.completed_packets, "0")

                # Advance by exactly 1 packet
                snap1 = eng.record_batch(
                    generated_delta=1,
                    started_delta=1,
                    succeeded_delta=1,
                    dropped_delta=0,
                    error_delta=0,
                    elapsed_ns_delta=1000,
                    is_modeled_statistical=True,
                )
                expected_rem = str(int(b_str) - 1)
                self.assertEqual(snap1.remaining_packets, expected_rem)
                self.assertEqual(snap1.completed_packets, "1")
                self.assertEqual(snap1.modeled_statistical_packets, "1")
                self.assertEqual(snap1.individually_processed_packets, "0")

    def test_rejects_floats_scientific_notation_and_out_of_range(self) -> None:
        invalid_inputs: list[object] = [
            0,
            -1,
            10**16 + 1,
            "0",
            "-5",
            "10000000000000001",
            "1e16",
            "1000.0",
            "010",
            1.5,
            True,
        ]
        for bad in invalid_inputs:
            with self.subTest(bad=bad):
                with self.assertRaises((ValueError, TypeError)):
                    parse_exact_decimal_int(bad, field_name="test")  # type: ignore[arg-type]

    def test_ordering_invariants_prevent_unprocessed_counted_as_completed(self) -> None:
        eng = PacketCounterEngine("100")
        with self.assertRaises(CounterInvariantError):
            # Completed (10) > Started (5) must fail
            eng.record_batch(
                generated_delta=10,
                started_delta=5,
                succeeded_delta=10,
                dropped_delta=0,
                error_delta=0,
                elapsed_ns_delta=100,
            )


class TestPhase2ABotSimulatorAnd10GbpsModel(unittest.TestCase):
    """3 & 4. Virtual bot simulator (1..10^16), 10Gbps model, and 5-way separation."""

    def test_10_pow_16_bots_theoretical_rate_and_zero_spawned_vms(self) -> None:
        sim = VirtualBotSimulator("10000000000000000", group_count=16)
        snap = sim.snapshot()
        self.assertEqual(snap.target_virtual_bots, "10000000000000000")
        self.assertEqual(snap.target_virtual_bots_jp, "1京")
        self.assertEqual(snap.actual_spawned_processes, 0)
        self.assertEqual(snap.actual_running_vms, 0)
        self.assertEqual(snap.actual_logical_agents, 16)

        rates = snap.rates_five_way
        # 10^16 * 10 Gbps = 10^17 Gbps = 10^26 bit/s
        self.assertEqual(
            rates["theoretical_gbps"].value_str,
            "100000000000000000",
        )
        self.assertEqual(
            rates["theoretical_bps"].value_str,
            "100000000000000000000000000",
        )
        self.assertEqual(rates["theoretical_gbps"].category, MetricCategory.THEORETICAL)
        self.assertEqual(rates["simulated_bps"].category, MetricCategory.SIMULATED)
        self.assertEqual(rates["measured_bps"].category, MetricCategory.UNVERIFIED)
        self.assertIsNone(rates["measured_bps"].value_str)
        self.assertEqual(
            rates["physical_100_exa_bps"].category, MetricCategory.UNMEASURABLE
        )
        self.assertIsNone(rates["physical_100_exa_bps"].value_str)

        # Fake measured metric without PASS must raise ValueError
        with self.assertRaises(ValueError):
            LabeledMetric(
                name="fake_measured",
                category=MetricCategory.MEASURED,
                value_str="100",
                unit="Gbps",
                note="Invalid without PASS",
                verification_status=Verdict.NOT_TESTED,
            )


class TestPhase2ADeviceMonitorAndThresholdGuard(unittest.TestCase):
    """5. Read-only device monitoring, 3-way power separation, and threshold guard."""

    def test_power_3way_separation_and_unavailable_sensors(self) -> None:
        mon = DeviceMonitor(WORKSPACE_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bat_dir = root / "battery"
            ac_dir = root / "ac"
            bat_dir.mkdir()
            ac_dir.mkdir()
            (bat_dir / "uevent").write_text(
                "POWER_SUPPLY_CAPACITY=75\n"
                "POWER_SUPPLY_STATUS=Discharging\n"
                "POWER_SUPPLY_VOLTAGE_NOW=12000000\n"
                "POWER_SUPPLY_CURRENT_NOW=500000\n",
                encoding="utf-8",
            )
            (ac_dir / "uevent").write_text("POWER_SUPPLY_ONLINE=0\n", encoding="utf-8")

            sep = mon.read_power_and_battery_separated(power_supply_root=root)
            self.assertEqual(sep["battery_capacity_percent"].value, 75)
            self.assertEqual(
                sep["power_connection_state"].value,
                {"battery_status": "Discharging", "external_ac_online": False},
            )
            self.assertEqual(
                sep["power_consumption_direct_watts"].status,
                SensorStatus.DIRECT_SENSOR_UNAVAILABLE,
            )
            self.assertIsNone(sep["power_consumption_direct_watts"].value)
            # 12V * 0.5A = 6.00W derived
            self.assertEqual(
                sep["power_consumption_derived_watts"].status,
                SensorStatus.DERIVED_FROM_VOLTAGE_CURRENT,
            )
            self.assertEqual(sep["power_consumption_derived_watts"].value, "6.00")

            # Dummy 0 thermal zone must report UNAVAILABLE (value=None)
            therm_dir = root / "thermal_zone0"
            therm_dir.mkdir()
            (therm_dir / "temp").write_text("0\n", encoding="utf-8")
            temp_r = mon.read_temperature(thermal_root=therm_dir)
            self.assertEqual(temp_r.status, SensorStatus.UNAVAILABLE)
            self.assertIsNone(temp_r.value)

    def test_application_resource_threshold_guard_and_scope(self) -> None:
        guard = SafetyGuard(
            WORKSPACE_DIR,
            thresholds=ResourceThresholds(
                min_host_available_ram_mib=180,
                max_process_rss_mib=250,
                min_disk_free_mib=600,
            ),
        )
        receipt = guard.check_resource_limits(
            simulated_available_ram_mib=400,
            simulated_process_rss_mib=50,
            simulated_disk_free_mib=1200,
        )
        self.assertTrue(receipt.passed)
        self.assertEqual(receipt.control_scope, ControlScope.APPLICATION_THRESHOLD_GUARD)
        self.assertEqual(receipt.os_enforcement_status, Verdict.NOT_TESTED)

        with self.assertRaises(ResourceLimitExceededError):
            guard.check_resource_limits(
                simulated_available_ram_mib=100,  # Below 180 MiB
                simulated_process_rss_mib=50,
                simulated_disk_free_mib=1200,
            )


class TestPhase2ARedactionAndEvidenceReporting(unittest.TestCase):
    """6. Synthetic PII redaction, Fail-Closed blocking, and 4-section reporting."""

    def test_14_categories_redacted_using_synthetic_vectors(self) -> None:
        redactor = RedactionEngine(
            custom_sensitive_literals={
                "synthetic_operator_01": "[REDACTED_USER]",
                "synthetic-node-alpha.example.invalid": "[REDACTED_HOST]",
            },
            include_runtime_env_tokens=False,
        )
        synthetic_sample = (
            "User=synthetic_operator_01 Host=synthetic-node-alpha.example.invalid "
            "IPv4=198.51.100.42 IPv6=2001:db8:85a3::8a2e:370:7334 "
            "MAC=00:00:5e:00:53:af SSID= synthetic_lab_wifi "
            "Email=operator01@example.invalid Phone=+81-90-0000-0000 "
            "Token=Bearer SYNTHETIC_TOKEN_1234567890 "
            "Cookie: session_id=SYNTHETIC_SESSION_999999 "
            "password=SYNTHETIC_PASS_VALUE "
            "Stream=rtmps://ingest.example.invalid/live2/SYNTHETIC_STREAM_KEY_888 "
            "Path=/home/synthetic_operator_01/secret/config.json "
            "Auth=sudo: synthetic_operator_01 : TTY=pts/0 "
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_KEY_BODY\n-----END PRIVATE KEY-----"
        )
        redacted = redactor.redact_text(synthetic_sample)

        forbidden_Residuals = [
            "synthetic_operator_01",
            "synthetic-node-alpha.example.invalid",
            "198.51.100.42",
            "2001:db8:85a3",
            "00:00:5e:00:53:af",
            "synthetic_lab_wifi",
            "operator01@example.invalid",
            "+81-90-0000-0000",
            "SYNTHETIC_TOKEN_1234567890",
            "SYNTHETIC_SESSION_999999",
            "SYNTHETIC_PASS_VALUE",
            "SYNTHETIC_STREAM_KEY_888",
            "SYNTHETIC_PRIVATE_KEY_BODY",
        ]
        for token in forbidden_Residuals:
            self.assertNotIn(token, redacted, f"Synthetic token {token} leaked!")

    def test_redaction_failure_rejects_public_output_fail_closed(self) -> None:
        def inject_error() -> None:
            raise RuntimeError("Simulated tokenizer failure")

        failing_redactor = RedactionEngine(
            include_runtime_env_tokens=False,
            failure_injector=inject_error,
        )
        with self.assertRaises(RedactionFailClosedError):
            failing_redactor.redact_text("Public text that must be blocked on error")

        rec = EvidenceRecorder()
        rec.append_log("TEST_START", "Synthetic log message")
        bundle = rec.build_evidence_bundle(
            test_id="TEST-SYN-001",
            started_at="2026-10-29T16:00:00+09:00",
            ended_at="2026-10-29T16:00:01+09:00",
            target_program_version="0.2.0-phase2a",
            os_and_image_version={"guest_os": "mk1ai-secure-linux", "status": "NOT_BUILT"},
            vm_configuration={"mode": "PHASE2A_NO_VM"},
            environment_info={"env": "synthetic"},
            test_scenario={"id": "SCN-SYN-001"},
            config_parameters={"initial_off": True},
            random_seed="20261029",
            input_data_bytes=b"synthetic_payload",
            target_values={"packets": "10000000000000000"},
            measured_values={"real_tx": None, "status": "NOT_TESTED"},
            verdict=Verdict.PASS,
            reproduction_conditions={"cmd": "python3 -B -m unittest"},
            unverified_items=["OS isolation and real network TX are NOT TESTED in Phase 2A"],
        )
        with self.assertRaises(RedactionFailClosedError):
            rec.export_public_bundle(bundle, failing_redactor)

    def test_evidence_log_cap_and_report_4sections_and_anti_exaggeration(self) -> None:
        rec = EvidenceRecorder(max_log_entries=2)
        rec.append_log("E1", "First")
        rec.append_log("E2", "Second")
        self.assertTrue(rec.verify_chain_integrity())
        with self.assertRaises(AuditLogCapacityError):
            rec.append_log("E3", "Exceeds cap")

        clean_redactor = RedactionEngine(include_runtime_env_tokens=False)
        gen = ReportGenerator(clean_redactor)
        bundle = rec.build_evidence_bundle(
            test_id="TEST-SYN-002",
            started_at="2026-10-29T16:00:00+09:00",
            ended_at="2026-10-29T16:00:01+09:00",
            target_program_version="0.2.0-phase2a",
            os_and_image_version={"guest_os": "mk1ai-secure-linux", "status": "NOT_BUILT"},
            vm_configuration={"mode": "PHASE2A_NO_VM"},
            environment_info={"env": "synthetic"},
            test_scenario={"id": "SCN-SYN-002"},
            config_parameters={"initial_off": True},
            random_seed="20261029",
            input_data_bytes=b"synthetic",
            target_values={"packets": "100"},
            measured_values={"real_tx": None},
            verdict=Verdict.PASS,
            reproduction_conditions={"cmd": "unittest"},
            unverified_items=["Real VM launch and XDP load: NOT TESTED"],
        )
        self.assertEqual(set(bundle.keys()), set(REQUIRED_16_EVIDENCE_KEYS))

        md = gen.generate_markdown_report(
            evidence_bundle=bundle,
            confirmed_by_evidence=["Application-level switch locks verified"],
            static_analysis_candidates=["Schema validation rules"],
            estimations_or_concerns=["Theoretical 10Gbps per bot model"],
            unverified_items=["OS-level isolation: NOT TESTED"],
            capability_matrix={
                "app_switch_lock": Verdict.PASS,
                "os_isolation": Verdict.NOT_TESTED,
            },
        )
        self.assertIn(REDACTION_LIMITATION_DISCLOSURE, md)
        self.assertIn("NOT TESTED", md)

        with self.assertRaises(ExaggeratedClaimError):
            gen.validate_no_exaggerated_claims("本システムは脆弱性ゼロで完全な安全性を保証します")


class TestPhase2APreviewUIAndRollbackVerifier(unittest.TestCase):
    """7 & Rollback: Safe non-networked preview UI and hash-verified rollback verifier."""

    def test_preview_ui_offline_stream_config_and_prohibited_actions(self) -> None:
        cfg = ConfigManager()
        guard = SafetyGuard(WORKSPACE_DIR)
        redactor = RedactionEngine(include_runtime_env_tokens=False)
        pkt = PacketCounterEngine("10000000000000000")
        bot = VirtualBotSimulator("10000000000000000")
        mon = DeviceMonitor(WORKSPACE_DIR)

        ui = PreviewAppController(
            workspace_dir=WORKSPACE_DIR,
            config=cfg,
            safety_guard=guard,
            redactor=redactor,
            packet_engine=pkt,
            bot_simulator=bot,
            device_monitor=mon,
        )
        res = ui.configure_stream_endpoint_offline(
            "rtmps://ingest.example.invalid/live2",
            "SYNTHETIC_STREAM_KEY_SECRET_999",
        )
        self.assertEqual(res["network_connections_opened"], 0)
        self.assertFalse(res["live_streaming_active"])
        self.assertNotIn("SYNTHETIC_STREAM_KEY_SECRET_999", res["masked_endpoint"])

        state = ui.build_sanitized_ui_state()
        self.assertEqual(state["prestream_safety_check"]["verdict"], "BLOCKED")
        self.assertEqual(len(state["all_10_states"]), 10)
        self.assertEqual(len(state["scenes"]), 7)

        for action in SafetyGuard.PROHIBITED_OPERATIONS_PHASE2A:
            with self.assertRaises(ProhibitedPhase2AOperationError):
                ui.attempt_prohibited_action(action)

        html = ui.render_static_preview_html()
        self.assertIn("BigInt(state.packet_counter.target_packets)", html)
        self.assertNotIn("SYNTHETIC_STREAM_KEY_SECRET_999", html)

    def test_rollback_verifier_rejects_self_reference_symlinks_unknown_and_locks_delete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            p1_file = ws / "DESIGN.md"
            p1_file.write_text("Phase 1 protected content\n", encoding="utf-8")
            p1_sha = compute_file_sha256(p1_file)

            p2_file = ws / "module.py"
            p2_file.write_text("print('phase 2a')\n", encoding="utf-8")
            p2_sha = compute_file_sha256(p2_file)

            unknown_file = ws / "untracked.txt"
            unknown_file.write_text("unknown\n", encoding="utf-8")

            sym_file = ws / "bad_link.py"
            sym_file.symlink_to(p2_file)

            manifest_path = ws / "phase2a_file_manifest.json"
            manifest_data = {
                "schema_version": 1,
                "files": {
                    "DESIGN.md": {
                        "sha256": p1_sha,
                        "size_bytes": p1_file.stat().st_size,
                        "preexisting_protected": True,
                        "owner_phase": "PHASE_1",
                    },
                    "module.py": {
                        "sha256": p2_sha,
                        "size_bytes": p2_file.stat().st_size,
                        "preexisting_protected": False,
                        "owner_phase": "PHASE_2A",
                    },
                },
            }
            manifest_path.write_text(
                json.dumps(manifest_data, indent=2), encoding="utf-8"
            )
            manifest_sha = compute_file_sha256(manifest_path)

            verifier = RollbackVerifier(ws)
            report = verifier.verify_manifest_and_workspace(manifest_path, manifest_sha)
            by_path = {d["relative_path"]: d for d in report["decisions"]}

            self.assertFalse(by_path["DESIGN.md"]["eligible_for_phase2a_rollback"])
            self.assertEqual(by_path["DESIGN.md"]["status"], "PROTECTED_PHASE1_INTACT")

            self.assertTrue(by_path["module.py"]["eligible_for_phase2a_rollback"])
            self.assertEqual(by_path["module.py"]["status"], "VERIFIED_PHASE2A_CANDIDATE")

            self.assertFalse(by_path["untracked.txt"]["eligible_for_phase2a_rollback"])
            self.assertEqual(by_path["untracked.txt"]["status"], "REJECTED_UNKNOWN_FILE")

            self.assertFalse(by_path["bad_link.py"]["eligible_for_phase2a_rollback"])
            self.assertEqual(by_path["bad_link.py"]["status"], "REJECTED_SYMLINK")

            # Tamper with module.py and verify hash mismatch rejection
            p2_file.write_text("print('modified')\n", encoding="utf-8")
            report2 = verifier.verify_manifest_and_workspace(manifest_path, manifest_sha)
            by_path2 = {d["relative_path"]: d for d in report2["decisions"]}
            self.assertFalse(by_path2["module.py"]["eligible_for_phase2a_rollback"])
            self.assertEqual(
                by_path2["module.py"]["status"], "REJECTED_HASH_OR_SIZE_MISMATCH"
            )

            # Circular self-reference in manifest must raise ManifestVerificationError
            manifest_data["files"]["phase2a_file_manifest.json"] = {
                "sha256": "0" * 64,
                "size_bytes": 10,
                "preexisting_protected": False,
                "owner_phase": "PHASE_2A",
            }
            manifest_path.write_text(
                json.dumps(manifest_data, indent=2), encoding="utf-8"
            )
            bad_manifest_sha = compute_file_sha256(manifest_path)
            with self.assertRaises(ManifestVerificationError):
                verifier.verify_manifest_and_workspace(manifest_path, bad_manifest_sha)

            # Deletion itself must be unconditionally blocked
            with self.assertRaises(DeletionNotApprovedError):
                verifier.execute_deletion()


if __name__ == "__main__":
    unittest.main()
