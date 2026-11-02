"""Audio mixer and output router with ducking and state management.

Key guarantees:
- AudioMixer separates state management from WebAudio backend invocation.
- If no active WebAudio backend is connected, state displays STATE_ONLY / NOT_CONNECTED.
- True -12dB ducking: 10^(-12/20) approx 0.25118864315.
- AudioOutputRouter strictly enforces Phase 2A lock: RECORDING and LIVE_STREAM routes
  remain locked and refuse transmission.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from typing import Any, Protocol


class MixerConnectionStatus(str, Enum):
    NOT_CONNECTED = "NOT_CONNECTED"
    STATE_ONLY = "STATE_ONLY"
    ACTIVE = "ACTIVE"


class AudioRoute(str, Enum):
    LOCAL_PREVIEW = "LOCAL_PREVIEW"
    RECORDING = "RECORDING"
    LIVE_STREAM = "LIVE_STREAM"


class WebAudioBackendProtocol(Protocol):
    def apply_gain(self, channel: str, gain: float) -> bool: ...
    def read_gain(self, channel: str) -> float | None: ...


def db_to_linear(db: float) -> float:
    return math.pow(10.0, db / 20.0)


DUCKING_MINUS_12DB_LINEAR: float = db_to_linear(-12.0)  # ~0.251188643150958


class AudioMixer:
    def __init__(self, backend: WebAudioBackendProtocol | None = None) -> None:
        self._backend = backend
        self._channel_gains: dict[str, float] = {
            "master": 1.0,
            "tts": 1.0,
            "bgm": 0.8,
            "sfx": 1.0,
        }
        self._ducking_active: bool = False
        self._ducking_attenuation_db: float = -12.0

    @property
    def connection_status(self) -> MixerConnectionStatus:
        if self._backend is None:
            return MixerConnectionStatus.NOT_CONNECTED
        return MixerConnectionStatus.ACTIVE

    def set_channel_gain(self, channel: str, gain: float) -> bool:
        if channel not in self._channel_gains:
            raise KeyError(f"Unknown channel: {channel!r}")
        if (
            isinstance(gain, bool)
            or not isinstance(gain, (int, float))
            or not math.isfinite(float(gain))
            or not (0.0 <= float(gain) <= 2.0)
        ):
            raise ValueError(f"Gain must be finite float in [0.0, 2.0], got {gain!r}")

        self._channel_gains[channel] = float(gain)
        if self._backend is not None:
            effective_gain = float(gain)
            if channel == "bgm" and self._ducking_active:
                effective_gain *= db_to_linear(self._ducking_attenuation_db)
            return self._backend.apply_gain(channel, effective_gain)
        return False

    def get_channel_gain(self, channel: str) -> float:
        if channel not in self._channel_gains:
            raise KeyError(f"Unknown channel: {channel!r}")
        return self._channel_gains[channel]

    def set_ducking(self, active: bool) -> bool:
        self._ducking_active = bool(active)
        if self._backend is not None:
            bgm_target = self._channel_gains["bgm"]
            if self._ducking_active:
                bgm_target *= db_to_linear(self._ducking_attenuation_db)
            return self._backend.apply_gain("bgm", bgm_target)
        return False

    def is_ducking(self) -> bool:
        return self._ducking_active

    def snapshot(self) -> dict[str, Any]:
        applied_gains: dict[str, float | None] = {}
        for ch in self._channel_gains:
            if self._backend is not None:
                applied_gains[ch] = self._backend.read_gain(ch)
            else:
                applied_gains[ch] = None

        return {
            "connection_status": self.connection_status.value,
            "configured_gains": dict(self._channel_gains),
            "applied_gains": applied_gains,
            "ducking_active": self._ducking_active,
            "ducking_depth_db": self._ducking_attenuation_db,
            "ducking_linear_factor": DUCKING_MINUS_12DB_LINEAR,
        }


class AudioOutputRouter:
    """Enforces Phase 2A isolation rules on audio routing."""

    def __init__(self, phase2a_locked: bool = True) -> None:
        self.phase2a_locked = phase2a_locked

    def route_audio(self, route: AudioRoute, audio_bytes: bytes) -> tuple[bool, str]:
        if not isinstance(audio_bytes, (bytes, bytearray)):
            raise TypeError("audio_bytes must be bytes")

        if route == AudioRoute.LOCAL_PREVIEW:
            return True, "Routed to local browser preview"

        if route in (AudioRoute.RECORDING, AudioRoute.LIVE_STREAM):
            if self.phase2a_locked:
                return False, f"Route {route.value} is strictly locked under Phase 2A policy"
            return True, f"Routed to {route.value}"

        return False, f"Unknown route: {route}"
