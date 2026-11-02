"""TTS Manager with license checks, fail-closed redaction, and strict PCM audio contracts.

Key guarantees:
- Adapters: UnavailableTTSAdapter (OpenJTalk / VOICEVOX marked UNAVAILABLE) and
  SyntheticToneAdapter (math sine wave / audio test tone, explicitly NOT real speech).
- Per-use license verification: Requests for commercial, recording, monetized stream,
  or unverified models are strictly rejected.
- Fail-closed redaction: All text passes through RedactionEngine. If redaction fails
  or an idempotent second pass detects unredacted tokens, speech is rejected.
- AudioChunk contract: Validates PCM format (s16le), sample rate, channels, byte length,
  and duration consistency.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import struct
from typing import Any, Callable

from aegislab.audio.speech_queue import (
    SpeechQueue,
    SpeechPriority,
    SpeechCategory,
    SpeechItem,
    PreemptOutcome,
    StopOutcome,
)
from aegislab.audio.voice_registry import (
    VoiceLicenseRegistry,
    UseCase,
    ModelKind,
)
from aegislab.privacy.redactor import RedactionEngine, RedactionFailClosedError


class AdapterKind(str, Enum):
    REAL_ENGINE = "REAL_ENGINE"
    TEST_SIGNAL = "TEST_SIGNAL"


class TTSAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class TTSManagerStatus(str, Enum):
    IDLE = "IDLE"
    SYNTHESIZING = "SYNTHESIZING"
    PLAYING = "PLAYING"
    STOPPED = "STOPPED"
    STOP_UNCONFIRMED = "STOP_UNCONFIRMED"
    FAULT = "FAULT"


@dataclass(frozen=True)
class AudioChunk:
    pcm_bytes: bytes
    sample_rate: int
    channels: int
    duration_sec: float

    def __post_init__(self) -> None:
        if not isinstance(self.pcm_bytes, (bytes, bytearray)):
            raise TypeError("pcm_bytes must be bytes")
        if self.sample_rate not in (16000, 22050, 24000, 44100, 48000):
            raise ValueError(f"Unsupported sample_rate: {self.sample_rate}")
        if self.channels not in (1, 2):
            raise ValueError(f"Unsupported channels: {self.channels}")
        bytes_per_sample = 2 * self.channels
        if len(self.pcm_bytes) % bytes_per_sample != 0:
            raise ValueError("pcm_bytes length must be multiple of bytes_per_sample")
        expected_samples = len(self.pcm_bytes) // bytes_per_sample
        calc_dur = expected_samples / self.sample_rate
        if abs(calc_dur - self.duration_sec) > 0.05:
            raise ValueError("duration_sec does not match PCM byte length")


class BaseTTSAdapter:
    adapter_id: str
    kind: AdapterKind

    def availability(self) -> TTSAvailability:
        raise NotImplementedError

    def synthesize(self, text: str, model_id: str, speed: float = 1.0) -> AudioChunk:
        raise NotImplementedError

    def stop(self) -> bool:
        return True


class UnavailableTTSAdapter(BaseTTSAdapter):
    def __init__(self, adapter_id: str, engine_name: str) -> None:
        self.adapter_id = adapter_id
        self.engine_name = engine_name
        self.kind = AdapterKind.REAL_ENGINE

    def availability(self) -> TTSAvailability:
        return TTSAvailability.UNAVAILABLE

    def synthesize(self, text: str, model_id: str, speed: float = 1.0) -> AudioChunk:
        raise RuntimeError(f"Engine {self.engine_name!r} is UNAVAILABLE in this environment")


class SyntheticToneAdapter(BaseTTSAdapter):
    """Produces a synthetic sine tone PCM chunk for local test signals."""

    def __init__(self, adapter_id: str = "synthetic_internal") -> None:
        self.adapter_id = adapter_id
        self.kind = AdapterKind.TEST_SIGNAL

    def availability(self) -> TTSAvailability:
        return TTSAvailability.AVAILABLE

    def synthesize(self, text: str, model_id: str, speed: float = 1.0) -> AudioChunk:
        # Generates a brief 440 Hz beep (0.3s)
        sample_rate = 16000
        channels = 1
        duration_sec = 0.3
        num_samples = int(sample_rate * duration_sec)
        freq = 440.0
        buf = bytearray()
        for i in range(num_samples):
            val = int(16000.0 * math.sin(2.0 * math.pi * freq * (i / sample_rate)))
            buf.extend(struct.pack("<h", max(-32768, min(32767, val))))
        return AudioChunk(
            pcm_bytes=bytes(buf),
            sample_rate=sample_rate,
            channels=channels,
            duration_sec=duration_sec,
        )


@dataclass(frozen=True)
class SpeechRequestResult:
    accepted: bool
    reason: str
    redacted_text: str = ""
    item_id: str | None = None


class TTSManager:
    def __init__(
        self,
        *,
        registry: VoiceLicenseRegistry,
        queue: SpeechQueue,
        redactor: RedactionEngine,
        auto_narration_enabled_cb: Callable[[], bool] | None = None,
    ) -> None:
        self.registry = registry
        self.queue = queue
        self.redactor = redactor
        self._auto_narration_enabled_cb = auto_narration_enabled_cb
        self._adapters: dict[str, BaseTTSAdapter] = {}
        self._status = TTSManagerStatus.IDLE

        # Register default adapters
        self.register_adapter(SyntheticToneAdapter("synthetic_internal"))
        self.register_adapter(UnavailableTTSAdapter("open_jtalk", "Open JTalk"))
        self.register_adapter(UnavailableTTSAdapter("voicevox", "VOICEVOX"))

    def register_adapter(self, adapter: BaseTTSAdapter) -> None:
        self._adapters[adapter.adapter_id] = adapter

    def request_speech(
        self,
        raw_text: str,
        *,
        engine_id: str,
        model_id: str,
        priority: SpeechPriority = SpeechPriority.NORMAL,
        category: SpeechCategory = SpeechCategory.OPERATOR_NOTICE,
        intended_use: UseCase = UseCase.LOCAL_PRIVATE_PREVIEW,
    ) -> SpeechRequestResult:
        if self._auto_narration_enabled_cb is not None:
            if not self._auto_narration_enabled_cb():
                return SpeechRequestResult(False, "Auto narration is disabled in configuration")

        # 1. License Check
        lic = self.registry.evaluate_use_case(engine_id, model_id, intended_use)
        if not lic.allowed:
            return SpeechRequestResult(False, f"License refused: {'; '.join(lic.reasons)}")

        # 2. Engine availability
        adapter = self._adapters.get(engine_id)
        if not adapter:
            return SpeechRequestResult(False, f"Engine adapter {engine_id!r} not found")
        if adapter.availability() != TTSAvailability.AVAILABLE:
            return SpeechRequestResult(False, f"Engine adapter {engine_id!r} is UNAVAILABLE")

        # 3. Privacy Redaction (fail-closed)
        try:
            redacted = self.redactor.redact_text(raw_text)
            # Second-pass idempotency verification
            second = self.redactor.redact_text(redacted)
            if second != redacted:
                return SpeechRequestResult(False, "Redaction failed idempotency check")
        except RedactionFailClosedError as exc:
            return SpeechRequestResult(False, f"Redaction fail-closed error: {type(exc).__name__}")
        except Exception as exc:
            return SpeechRequestResult(False, f"Redaction unexpected error: {type(exc).__name__}")

        # 4. Enqueue
        eq_res = self.queue.enqueue(
            redacted,
            priority=priority,
            category=category,
            engine_id=engine_id,
            model_id=model_id,
        )
        if not eq_res.accepted:
            return SpeechRequestResult(False, f"Queue refused: {eq_res.reason}", redacted_text=redacted)

        return SpeechRequestResult(
            accepted=True,
            reason="enqueued",
            redacted_text=redacted,
            item_id=eq_res.item.item_id if eq_res.item else None,
        )

    def synthesize_and_get_chunk(self, item: SpeechItem) -> AudioChunk:
        adapter = self._adapters.get(item.engine_id)
        if not adapter or adapter.availability() != TTSAvailability.AVAILABLE:
            raise RuntimeError(f"Engine {item.engine_id} unavailable at synthesis time")
        return adapter.synthesize(item.text, item.model_id)

    def stop_all(self, stop_active_cb: Callable[[], bool] | None = None) -> StopOutcome:
        res = self.queue.stop_all(stop_active_cb)
        if res == StopOutcome.STOPPED:
            self._status = TTSManagerStatus.STOPPED
        else:
            self._status = TTSManagerStatus.STOP_UNCONFIRMED
        return res

    def snapshot(self) -> dict[str, Any]:
        return {
            "status": self._status.value,
            "queue": self.queue.snapshot(),
            "adapters": {k: v.availability().value for k, v in self._adapters.items()},
        }
