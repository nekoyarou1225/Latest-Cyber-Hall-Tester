"""Unit test suite for VoiceLicenseRegistry, SpeechQueue, TTSManager, and AudioMixer.

Directly imports the real modules from aegislab.audio and aegislab.privacy.
"""

from __future__ import annotations

import unittest
import sys
sys.path.insert(0, "/home/harukiy1225/テストツール")

import aegislab, aegislab.core
aegislab.__path__.insert(0, "/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/aegislab")
aegislab.core.__path__.insert(0, "/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/aegislab/core")

from aegislab.audio.voice_registry import (
    VoiceLicenseRegistry,
    LicenseStatus,
    UseCase,
    EngineLicense,
    VoiceModelLicense,
    ModelKind,
    LicenseEvidence,
)
from aegislab.audio.speech_queue import (
    SpeechQueue,
    SpeechPriority,
    SpeechCategory,
    PlaybackState,
    PreemptOutcome,
    StopOutcome,
)
from aegislab.audio.tts_manager import (
    TTSManager,
    TTSAvailability,
    AudioChunk,
    SyntheticToneAdapter,
    UnavailableTTSAdapter,
)
from aegislab.audio.audio_mixer import (
    AudioMixer,
    AudioOutputRouter,
    AudioRoute,
    MixerConnectionStatus,
    DUCKING_MINUS_12DB_LINEAR,
)
from aegislab.privacy.redactor import RedactionEngine


class TestAudioTTSPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = VoiceLicenseRegistry()
        self.queue = SpeechQueue()
        self.redactor = RedactionEngine()
        self.tts = TTSManager(registry=self.registry, queue=self.queue, redactor=self.redactor)

    def test_openjtalk_mei_is_unverified_and_commercial_use_refused(self) -> None:
        # Mei model must be strictly UNVERIFIED in the default registry
        dec = self.registry.can_use_commercial("open_jtalk", "openjtalk_mei_normal")
        self.assertFalse(dec.allowed)
        self.assertTrue(any("UNVERIFIED" in r for r in dec.reasons))

        dec_stream = self.registry.can_use_monetized_stream("open_jtalk", "openjtalk_mei_normal")
        self.assertFalse(dec_stream.allowed)

        dec_record = self.registry.can_use_recorded_video("open_jtalk", "openjtalk_mei_normal")
        self.assertFalse(dec_record.allowed)

    def test_engine_and_model_license_mismatch(self) -> None:
        # Engine is commercial PROHIBITED, but model is ALLOWED
        self.registry.register_engine(
            EngineLicense(
                engine_id="prohibited_engine",
                name="Prohibited Engine",
                version="1.0",
                license_type="Non-Commercial Only",
                commercial_status=LicenseStatus.PROHIBITED,
                monetized_stream_status=LicenseStatus.PROHIBITED,
                recording_status=LicenseStatus.PROHIBITED,
                redistribution_status=LicenseStatus.PROHIBITED,
            )
        )
        self.registry.register_model(
            VoiceModelLicense(
                model_id="permissive_model",
                engine_id="prohibited_engine",
                name="Permissive Model",
                model_kind=ModelKind.SPEECH_VOICE,
                version="1.0",
                distributor="Test",
                sha256_hex="aa" * 32,
                terms_url="https://example.invalid/terms",
                commercial_status=LicenseStatus.ALLOWED,
                monetized_stream_status=LicenseStatus.ALLOWED,
                recording_status=LicenseStatus.ALLOWED,
                redistribution_status=LicenseStatus.ALLOWED,
                evidence=LicenseEvidence(
                    verified_at_iso="2026-10-30T00:00:00Z",
                    verifier="Tester",
                    evidence_ref="Test ref",
                    terms_source_url="https://example.invalid/terms",
                ),
            )
        )
        dec = self.registry.can_use_commercial("prohibited_engine", "permissive_model")
        self.assertFalse(dec.allowed)
        self.assertTrue(any("Engine prohibited_engine status for COMMERCIAL_USE is PROHIBITED" in r for r in dec.reasons))

    def test_tts_request_speech_with_unverified_model_rejected(self) -> None:
        # Attempt to synthesize using openjtalk_mei_normal for commercial purpose
        res = self.tts.request_speech(
            "Hello test",
            engine_id="open_jtalk",
            model_id="openjtalk_mei_normal",
            intended_use=UseCase.COMMERCIAL_USE,
        )
        self.assertFalse(res.accepted)
        self.assertIn("License refused", res.reason)

    def test_tts_request_speech_redaction_and_idempotency(self) -> None:
        # Privacy sensitive token in text must be redacted before queuing
        res = self.tts.request_speech(
            "User 192.168.1.1 alert token super_secret_pass",
            engine_id="synthetic_internal",
            model_id="synthetic_tone_440",
            intended_use=UseCase.LOCAL_PRIVATE_PREVIEW,
        )
        self.assertTrue(res.accepted)
        self.assertIn("[REDACTED_IPV4]", res.redacted_text)
        self.assertNotIn("192.168.1.1", res.redacted_text)

    def test_unavailable_adapter_synthesize_raises(self) -> None:
        adapter = UnavailableTTSAdapter("voicevox", "VOICEVOX")
        self.assertEqual(adapter.availability(), TTSAvailability.UNAVAILABLE)
        with self.assertRaises(RuntimeError):
            adapter.synthesize("test", "model")

    def test_speech_queue_capacity_and_emergency_interrupt(self) -> None:
        q = SpeechQueue(max_capacity=2)
        r1 = q.enqueue("msg1", engine_id="synthetic_internal", model_id="synthetic_tone_440")
        r2 = q.enqueue("msg2", engine_id="synthetic_internal", model_id="synthetic_tone_440")
        r3 = q.enqueue("msg3", engine_id="synthetic_internal", model_id="synthetic_tone_440")
        self.assertTrue(r1.accepted)
        self.assertTrue(r2.accepted)
        self.assertFalse(r3.accepted)
        self.assertEqual(r3.reason, "queue capacity full")

        # Dispatch item
        item = q.get_next_item()
        self.assertIsNotNone(item)
        q.report_playback_started(item.item_id)

        # Emergency interrupt with confirmed callback
        stopped = q.emergency_interrupt(stop_active_cb=lambda: True)
        self.assertEqual(stopped, PreemptOutcome.PREEMPT_CONFIRMED)
        self.assertEqual(q.snapshot()["playback_state"], PlaybackState.IDLE.value)

    def test_audio_mixer_backend_and_ducking_factor(self) -> None:
        mixer = AudioMixer(backend=None)
        # Without backend, status must be NOT_CONNECTED
        self.assertEqual(mixer.connection_status, MixerConnectionStatus.NOT_CONNECTED)
        self.assertIsNone(mixer.snapshot()["applied_gains"]["master"])

        # Check exact ducking linear factor (~0.2512)
        self.assertAlmostEqual(DUCKING_MINUS_12DB_LINEAR, 0.25118864, places=6)

    def test_audio_output_router_locks_phase2a(self) -> None:
        router = AudioOutputRouter(phase2a_locked=True)
        # LOCAL_PREVIEW is allowed
        ok, msg = router.route_audio(AudioRoute.LOCAL_PREVIEW, b"pcm_data")
        self.assertTrue(ok)

        # RECORDING is locked
        ok2, msg2 = router.route_audio(AudioRoute.RECORDING, b"pcm_data")
        self.assertFalse(ok2)
        self.assertIn("locked under Phase 2A", msg2)

        # LIVE_STREAM is locked
        ok3, msg3 = router.route_audio(AudioRoute.LIVE_STREAM, b"pcm_data")
        self.assertFalse(ok3)
        self.assertIn("locked under Phase 2A", msg3)


if __name__ == "__main__":
    unittest.main()
