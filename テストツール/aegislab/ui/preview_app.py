"""OBS-Style Preview UI State Controller & Static HTML/JS Generator (Modules 14, 15, 16, 17).

Enforces:
- Does NOT start real network traffic, screen capture, microphone capture,
  recording, or live streaming.
- Displays all 10 operational states, 7 scenes, 14 layout docks, and exact BigInt
  counters up to 10^16 (1京).
- Explicitly displays unexecuted/prohibited features as `NOT TESTED` (disabled in Phase 2A).
- Entering a streaming endpoint only stores the redacted configuration (`CONFIGURED_OFFLINE`)
  and never initiates a network connection.
- Applies Fail-Closed redaction via RedactionEngine before emitting any preview state or HTML.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegislab.core.config_manager import ConfigManager
from aegislab.core.safety_guard import SafetyGuard
from aegislab.core.value_types import SystemState, Verdict
from aegislab.monitor.device_monitor import DeviceMonitor
from aegislab.privacy.redactor import RedactionEngine
from aegislab.sim.bot_simulator import VirtualBotSimulator
from aegislab.sim.packet_counter import PacketCounterEngine

STANDARD_SCENES: tuple[dict[str, str], ...] = (
    {"id": "SCENE_OVERVIEW", "title": "1. テスト概要"},
    {"id": "SCENE_PACKETS", "title": "2. パケット処理状況 (1〜1京)"},
    {"id": "SCENE_BOTS", "title": "3. 仮想ボットの状態 (1〜1京 & 10Gbps理論モデル)"},
    {"id": "SCENE_RESOURCES", "title": "4. デバイスリソース状況 (初期OFF)"},
    {"id": "SCENE_DPI", "title": "5. DPI検証結果"},
    {"id": "SCENE_XDP", "title": "6. XDP/eBPF 9段階検証ステータス"},
    {"id": "SCENE_REPORT", "title": "7. テスト完了レポート"},
)

XDP_NINE_STAGES_DEFAULT: tuple[dict[str, str], ...] = (
    {"stage": "1", "name": "ソースコードが存在する", "status": Verdict.NOT_TESTED.value, "detail": "eBPF/XDP カーネルプログラム (*.bpf.c) は Phase 2A で未作成 (NOT TESTED)"},
    {"stage": "2", "name": "コンパイルに成功した", "status": Verdict.NOT_TESTED.value, "detail": "clang/llvm 未導入および Phase 2A 禁止事項のため未実行 (NOT TESTED)"},
    {"stage": "3", "name": "対応カーネルが利用可能である", "status": "CONFIRMED (Kernel 6.6.147)", "detail": "Linux 6.6.147 x86_64 の存在を読み取り専用で確認済み"},
    {"stage": "4", "name": "必要な権限や機能が利用可能である", "status": Verdict.NOT_TESTED.value, "detail": "/sys/fs/bpf 非特権アクセス不可・bpftool不在・Phase 2A 禁止事項 (NOT TESTED)"},
    {"stage": "5", "name": "プログラムのロードに成功した", "status": Verdict.NOT_TESTED.value, "detail": "Phase 2A で XDP ロード禁止のため未実行 (NOT TESTED)"},
    {"stage": "6", "name": "対象インターフェースへ接続できた", "status": Verdict.NOT_TESTED.value, "detail": "Phase 2A でインターフェース変更禁止のため未実行 (NOT TESTED)"},
    {"stage": "7", "name": "意図したパケット経路で実行された", "status": Verdict.NOT_TESTED.value, "detail": "Phase 2A で実通信禁止のため未実行 (NOT TESTED)"},
    {"stage": "8", "name": "期待した PASS/DROP/REDIRECT 動作が確認された", "status": Verdict.NOT_TESTED.value, "detail": "未実行 (NOT TESTED)"},
    {"stage": "9", "name": "実測証拠で動作を確認した", "status": Verdict.NOT_TESTED.value, "detail": "未実行 (NOT TESTED)"},
)


class PreviewAppController:
    """Manages OBS-style preview UI state without starting network, recording, or streaming."""

    def __init__(
        self,
        *,
        workspace_dir: Path,
        config: ConfigManager,
        safety_guard: SafetyGuard,
        redactor: RedactionEngine,
        packet_engine: PacketCounterEngine,
        bot_simulator: VirtualBotSimulator,
        device_monitor: DeviceMonitor,
        adaptive_controller: Any | None = None,
        tts_manager: Any | None = None,
        audio_mixer: Any | None = None,
    ) -> None:
        self._workspace_dir = workspace_dir
        self._config = config
        self._safety_guard = safety_guard
        self._redactor = redactor
        self._packet_engine = packet_engine
        self._bot_simulator = bot_simulator
        self._device_monitor = device_monitor
        self._adaptive_controller = adaptive_controller
        self._tts_manager = tts_manager
        self._audio_mixer = audio_mixer
        self._system_state: SystemState = SystemState.UNCONFIGURED
        self._active_scene_id: str = "SCENE_OVERVIEW"
        self._stream_state: str = "DISCONNECTED"
        self._configured_stream_url_masked: str = ""
        self._network_connections_opened: int = 0
        self._sources: list[dict[str, Any]] = [
            {
                "id": "src_test_header",
                "type": "text",
                "visible": True,
                "allowlisted": True,
                "inspected": True,
                "content": "Project AegisLab Phase 2A Safe Preview (All Optional Features OFF)",
            },
            {
                "id": "src_counter_overlay",
                "type": "counter",
                "visible": False,  # Overlay is OFF initially
                "allowlisted": True,
                "inspected": True,
                "content": "Target: 10,000,000,000,000,000 (1京) Packets [SIMULATED_ONLY]",
            },
        ]

    @property
    def stream_state(self) -> str:
        return self._stream_state

    @property
    def network_connections_opened(self) -> int:
        return self._network_connections_opened

    def set_system_state(self, new_state: SystemState) -> None:
        self._system_state = new_state

    def select_scene(self, scene_id: str) -> None:
        valid_ids = {s["id"] for s in STANDARD_SCENES}
        if scene_id not in valid_ids:
            raise ValueError(f"Unknown scene_id: {scene_id}")
        self._active_scene_id = scene_id

    def configure_stream_endpoint_offline(
        self,
        rtmps_url: str,
        stream_key: str,
    ) -> dict[str, Any]:
        """Step 1 of streaming: store masked endpoint offline without opening any connection."""
        if stream_key:
            self._redactor.register_sensitive_literal(
                stream_key, "[REDACTED_STREAM_KEY]"
            )
        combined = f"{rtmps_url.rstrip('/')}/{stream_key}" if stream_key else rtmps_url
        self._configured_stream_url_masked = self._redactor.redact_text(combined)
        self._stream_state = "CONFIGURED_OFFLINE_NO_CONNECTION"
        return {
            "stream_state": self._stream_state,
            "masked_endpoint": self._configured_stream_url_masked,
            "network_connections_opened": self._network_connections_opened,
            "live_streaming_active": False,
        }

    def attempt_prohibited_action(self, action_key: str) -> None:
        """Delegate to SafetyGuard to block prohibited Phase 2A actions."""
        self._safety_guard.guard_prohibited_operation(action_key)

    def build_sanitized_ui_state(self) -> dict[str, Any]:
        """Generate complete 14-dock UI state passed through RedactionEngine (Fail-Closed)."""
        receipt = self._safety_guard.check_resource_limits()
        prestream = self._redactor.evaluate_prestream_safety(
            sources=self._sources,
            screen_capture_on=self._config.get_optional_feature("screen_capture"),
            mic_on=self._config.get_optional_feature("microphone_input"),
            desktop_audio_on=self._config.get_optional_feature("desktop_audio_input"),
            phase2a_prohibition_active=True,
        )

        raw_state: dict[str, Any] = {
            "system_state": self._system_state.value,
            "all_10_states": [s.value for s in SystemState],
            "default_guest_os": {
                "os_id": self._config.default_guest_os,
                "status": self._config.default_guest_os_status,
                "verdict": Verdict.NOT_TESTED.value,
                "note": "Default is MK1Ai Secure Linux, explicitly shown as NOT BUILT / NOT TESTED in Phase 2A.",
            },
            "active_scene_id": self._active_scene_id,
            "scenes": list(STANDARD_SCENES),
            "sources": self._sources,
            "packet_counter": self._packet_engine.snapshot().to_dict(),
            "bot_simulator": self._bot_simulator.snapshot().to_dict(),
            "device_monitor": self._device_monitor.poll_snapshot(
                panel_enabled=self._config.get_optional_feature("device_monitoring_panel")
            ),
            "resource_threshold_guard": receipt.to_dict(),
            "optional_features": self._config.get_all_optional_features(),
            "mandatory_safety_controls": [
                c.to_dict() for c in self._config.get_detailed_mandatory_control_statuses()
            ],
            "xdp_nine_stages": list(XDP_NINE_STAGES_DEFAULT),
            "streaming_and_recording": {
                "stream_state": self._stream_state,
                "configured_endpoint_masked": self._configured_stream_url_masked,
                "network_connections_opened": self._network_connections_opened,
                "recording_active": False,
                "live_streaming_active": False,
                "phase2a_status": Verdict.NOT_TESTED.value,
            },
            "prestream_safety_check": prestream.to_dict(),
            "prohibited_phase2a_features_status": {
                k: Verdict.NOT_TESTED.value
                for k in sorted(SafetyGuard.PROHIBITED_OPERATIONS_PHASE2A.keys())
            },
            "adaptive_packet_control": (
                self._adaptive_controller.snapshot()
                if self._adaptive_controller is not None
                else "UNAVAILABLE"
            ),
            "tts_manager": (
                self._tts_manager.snapshot()
                if self._tts_manager is not None
                else "UNAVAILABLE"
            ),
            "audio_mixer": (
                self._audio_mixer.snapshot()
                if self._audio_mixer is not None
                else "UNAVAILABLE"
            ),
        }
        return self._redactor.redact_structure(raw_state)

    def render_static_preview_html(self) -> str:
        """Render a self-contained static HTML preview using BigInt for 1..10^16."""
        sanitized_state = self.build_sanitized_ui_state()
        state_json = json.dumps(sanitized_state, ensure_ascii=False, indent=2)
        html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<title>Project AegisLab × MK1Ai — Phase 2A Safe Preview UI</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #12161f; color: #e6edf3; margin: 0; padding: 16px; }}
  .banner {{ background: #1f2937; border: 1px solid #374151; padding: 12px; border-radius: 6px; margin-bottom: 16px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 12px; }}
  .dock {{ background: #1a202c; border: 1px solid #2d3748; border-radius: 6px; padding: 12px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; background: #374151; }}
  .mono {{ font-family: ui-monospace, monospace; word-break: break-all; }}
</style>
</head>
<body>
<div class="banner">
  <strong>Project AegisLab × MK1Ai (Phase 2A Non-Networked Preview)</strong> |
  全体状態: <span class="badge" id="state-badge">{sanitized_state['system_state']}</span> |
  デフォルトOS: <span class="badge">{sanitized_state['default_guest_os']['os_id']} ({sanitized_state['default_guest_os']['status']})</span> |
  配信可否判定: <span class="badge">{sanitized_state['prestream_safety_check']['verdict']}</span>
</div>
<div class="grid">
  <div class="dock">
    <h3>パケットカウンター (1〜1京 BigInt 完全精度)</h3>
    <div class="mono" id="pkt-target">Target: {sanitized_state['packet_counter']['target_packets']} ({sanitized_state['packet_counter']['target_packets_jp']})</div>
    <div class="mono" id="pkt-rem">Remaining: {sanitized_state['packet_counter']['remaining_packets']}</div>
  </div>
  <div class="dock">
    <h3>仮想ボット &amp; 10Gbps 理論モデル (5区分分離)</h3>
    <div class="mono">Target Bots: {sanitized_state['bot_simulator']['target_virtual_bots']} ({sanitized_state['bot_simulator']['target_virtual_bots_jp']})</div>
    <div class="mono">[理論値] {sanitized_state['bot_simulator']['rates_five_way']['theoretical_gbps']['value_str']} Gbps</div>
    <div class="mono">[実測値] {sanitized_state['bot_simulator']['rates_five_way']['measured_bps']['verification_status']} (実通信OFF)</div>
  </div>
</div>
<script id="aegislab-state-json" type="application/json">{state_json}</script>
<script>
  const state = JSON.parse(document.getElementById("aegislab-state-json").textContent);
  const targetBigInt = BigInt(state.packet_counter.target_packets);
  const completedBigInt = BigInt(state.packet_counter.completed_packets);
  const remainingBigInt = targetBigInt - completedBigInt;
  if (remainingBigInt.toString() !== state.packet_counter.remaining_packets) {{
    throw new Error("BigInt precision mismatch in UI");
  }}
</script>
</body>
</html>
"""
        return self._redactor.redact_text(html)
