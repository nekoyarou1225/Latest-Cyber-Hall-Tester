"""Unit test suite verifying HTML static consistency and PreviewApp integration.
"""

from __future__ import annotations

import html.parser
import unittest
import sys
sys.path.insert(0, "/home/harukiy1225/テストツール")

import aegislab, aegislab.core, aegislab.ui
aegislab.__path__.insert(0, "/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/aegislab")
aegislab.core.__path__.insert(0, "/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/aegislab/core")
aegislab.ui.__path__.insert(0, "/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/aegislab/ui")

from aegislab.core.config_manager import ConfigManager
from aegislab.core.safety_guard import SafetyGuard
from aegislab.privacy.redactor import RedactionEngine
from aegislab.sim.packet_counter import PacketCounterEngine
from aegislab.sim.bot_simulator import VirtualBotSimulator
from aegislab.monitor.device_monitor import DeviceMonitor
from aegislab.ui.preview_app import PreviewAppController
from aegislab.control.adaptive_packet_controller import AdaptivePacketController
from aegislab.audio.voice_registry import VoiceLicenseRegistry
from aegislab.audio.speech_queue import SpeechQueue
from aegislab.audio.tts_manager import TTSManager
from aegislab.audio.audio_mixer import AudioMixer
from pathlib import Path


class HTMLContentParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text_content: list[str] = []

    def handle_data(self, data: str) -> None:
        self.text_content.append(data.strip())


class TestHTMLAndUIIntegration(unittest.TestCase):
    def test_html_static_safety_and_labels(self) -> None:
        with open("/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/index.html", "r", encoding="utf-8") as f:
            html_text = f.read()

        # No external scripts, no CDN, no eval
        self.assertNotIn("http://", html_text)
        self.assertNotIn("https://", html_text)
        self.assertNotIn("<script src=", html_text)
        self.assertNotIn("eval(", html_text)

        # Mei must be UNVERIFIED, not ALLOWED or commercial free
        self.assertIn("UNVERIFIED", html_text)
        self.assertNotIn("商用フリー", html_text)
        self.assertNotIn("ALLOWED", html_text)

        # -12dB linear ducking factor is displayed correctly (~0.2512)
        self.assertIn("0.2512", html_text)

    def test_preview_app_integration_with_new_controllers(self) -> None:
        cfg = ConfigManager()
        sg = SafetyGuard(workspace_dir=Path("/home/harukiy1225/テストツール"))
        red = RedactionEngine()
        pke = PacketCounterEngine(1000)
        bot = VirtualBotSimulator(16)
        dev = DeviceMonitor(workspace_dir=Path("/home/harukiy1225/テストツール"))

        ctrl = AdaptivePacketController()
        reg = VoiceLicenseRegistry()
        q = SpeechQueue()
        tts = TTSManager(registry=reg, queue=q, redactor=red)
        mixer = AudioMixer()

        preview = PreviewAppController(
            workspace_dir=Path("/home/harukiy1225/テストツール"),
            config=cfg,
            safety_guard=sg,
            redactor=red,
            packet_engine=pke,
            bot_simulator=bot,
            device_monitor=dev,
            adaptive_controller=ctrl,
            tts_manager=tts,
            audio_mixer=mixer,
        )

        state = preview.build_sanitized_ui_state()
        self.assertIn("adaptive_packet_control", state)
        self.assertIn("tts_manager", state)
        self.assertIn("audio_mixer", state)
        self.assertEqual(state["adaptive_packet_control"]["state"], "IDLE")
        self.assertEqual(state["audio_mixer"]["connection_status"], "NOT_CONNECTED")


if __name__ == "__main__":
    unittest.main()
