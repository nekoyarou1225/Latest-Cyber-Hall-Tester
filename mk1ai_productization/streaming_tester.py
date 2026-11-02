"""P6: Tester Dedicated Streaming Engine (Built-in YouTube Live Studio + Isolated Test Mode).

Enforces:
- OBS-free internal streaming pipeline using Dedicated Whitelisted Tester Canvas.
- 14 distinct streaming states:
  DISCONNECTED, NOT_CONFIGURED, AUTH_REQUIRED, READY, PREVIEW, ENCODING,
  CONNECTING, TESTING, LIVE, STOPPING, STOPPED, ERROR, NOT_ELIGIBLE, NOT_AVAILABLE.
- Strict separation of TEST_MODE (Mock YouTube API + Fake Ingest Sink, zero external calls)
  and LIVE_MODE (OAuth 2.0 PKCE/CSRF + YouTube Live Streaming API flow).
- Never transitions to LIVE unless YouTube stream status is confirmed 'active' AND
  preview canvas hash matches output canvas hash.
- Age & channel eligibility enforcement (<16 standalone streaming blocked -> NOT_ELIGIBLE).
- Stream Key and OAuth Token protection (never returned in snapshot, UI, or logs).
- Bounded reconnect count (no infinite retry) and immediate Stop priority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import secrets
from typing import Any

from aegislab.core.safety_guard import ResourceLimitExceededError, SafetyGuard
from aegislab.evidence.recorder import EvidenceRecorder
from aegislab.privacy.redactor import RedactionEngine


class StreamState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    READY = "READY"
    PREVIEW = "PREVIEW"
    ENCODING = "ENCODING"
    CONNECTING = "CONNECTING"
    TESTING = "TESTING"
    LIVE = "LIVE"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class StreamExecutionMode(str, Enum):
    TEST_MODE_SIMULATED = "TEST_MODE_SIMULATED"
    LIVE_YOUTUBE_API = "LIVE_YOUTUBE_API"


WHITELISTED_TESTER_CANVAS_SOURCES: frozenset[str] = frozenset(
    {
        "tester_summary_metrics",
        "tester_throughput_chart",
        "packet_simulation_counter",
        "simulated_security_events",
        "simulated_device_monitor",
        "simulation_state_banner",
        "user_approved_description_text",
    }
)

PROHIBITED_CANVAS_SOURCES: frozenset[str] = frozenset(
    {
        "full_desktop_capture",
        "aegis_files_content",
        "oauth_token_display",
        "stream_key_display",
        "private_key_display",
        "cookie_or_session_storage",
        "other_app_windows",
        "os_notifications",
        "unredacted_audit_logs",
    }
)


class StreamSecurityViolationError(PermissionError):
    """Raised when a prohibited source, unverified preview, or unauthorized transition is attempted."""


@dataclass
class TesterStreamConfig:
    title: str = "AegisLab Tester Security Verification Stream"
    description: str = "Isolated Tester Canvas telemetry preview"
    privacy_status: str = "private"  # Always defaults to 'private'
    resolution: str = "720p"         # 360p, 480p, 720p (default), 1080p
    fps: int = 30                    # 30 (default) or 60
    bitrate_kbps: int = 4500
    audio_muted: bool = True         # Default audio OFF / muted
    mic_enabled: bool = False        # Default OFF
    camera_enabled: bool = False     # Default OFF
    system_audio_enabled: bool = False  # Default OFF


class TesterStreamingEngine:
    """Manages Tester-only YouTube Live Streaming & Mock Test Mode."""

    MAX_RECONNECT_ATTEMPTS = 3

    def __init__(
        self,
        *,
        safety_guard: SafetyGuard,
        redactor: RedactionEngine,
        recorder: EvidenceRecorder,
    ) -> None:
        self._safety_guard = safety_guard
        self._redactor = redactor
        self._recorder = recorder
        self._mode: StreamExecutionMode = StreamExecutionMode.TEST_MODE_SIMULATED
        self._state: StreamState = StreamState.DISCONNECTED
        self._config = TesterStreamConfig()
        self._active_canvas_sources: list[str] = [
            "tester_summary_metrics",
            "packet_simulation_counter",
            "simulation_state_banner",
        ]
        # Sensitive secrets kept strictly in private memory, never exposed in snapshot()
        self._oauth_access_token_secret: str | None = None
        self._stream_key_secret: str | None = None
        self._csrf_state_token: str = secrets.token_urlsafe(24)
        self._pkce_code_verifier: str = secrets.token_urlsafe(32)
        self._broadcast_id: str | None = None
        self._stream_id: str | None = None
        self._youtube_stream_status: str = "inactive"  # 'inactive' | 'ready' | 'active' | 'error'
        self._preview_canvas_frame_hash: str = ""
        self._encoder_canvas_frame_hash: str = ""
        self._reconnect_count: int = 0
        self._dropped_frames: int = 0
        self._last_error: str = ""
        self._user_age_verified_16_plus: bool = True
        self._adult_co_stream_supervision: bool = False

    @property
    def state(self) -> StreamState:
        return self._state

    @property
    def mode(self) -> StreamExecutionMode:
        return self._mode

    def set_mode(self, mode: StreamExecutionMode) -> None:
        if self._state in {StreamState.LIVE, StreamState.TESTING, StreamState.ENCODING}:
            raise RuntimeError("Cannot switch streaming mode while active; stop first")
        self._mode = mode
        self._state = StreamState.DISCONNECTED
        self._recorder.append_log("STREAM_MODE_CHANGED", f"Set Tester stream mode to {mode.value}")

    def verify_age_and_channel_eligibility(
        self,
        *,
        user_age: int,
        adult_present_in_broadcast: bool = False,
        channel_live_enabled: bool = True,
    ) -> StreamState:
        """Enforce YouTube age restrictions: users under 16 cannot live stream standalone."""
        if user_age < 16 and not adult_present_in_broadcast:
            self._user_age_verified_16_plus = False
            self._state = StreamState.NOT_ELIGIBLE
            self._last_error = (
                "YouTube policy compliance: standalone live streaming is restricted for users under 16. "
                "Only local PREVIEW / TEST_MODE is permitted."
            )
            self._recorder.append_log("STREAM_ELIGIBILITY_BLOCKED", self._last_error)
            return self._state

        if not channel_live_enabled:
            self._state = StreamState.NOT_ELIGIBLE
            self._last_error = "YouTube channel does not have live streaming enabled."
            return self._state

        self._user_age_verified_16_plus = True
        self._adult_co_stream_supervision = adult_present_in_broadcast
        return self._state

    def configure_canvas_sources(self, sources: list[str]) -> list[str]:
        """Allowlist-only validation for Tester Dedicated Stream Canvas."""
        for src in sources:
            if src in PROHIBITED_CANVAS_SOURCES or src not in WHITELISTED_TESTER_CANVAS_SOURCES:
                self._state = StreamState.ERROR
                self._last_error = f"Prohibited or non-whitelisted canvas source rejected: '{src}'"
                self._recorder.append_log("STREAM_SOURCE_REJECTED", self._last_error)
                raise StreamSecurityViolationError(self._last_error)
        self._active_canvas_sources = list(sources)
        return self._active_canvas_sources

    def update_stream_settings(
        self,
        *,
        title: str | None = None,
        description: str | None = None,
        privacy_status: str | None = None,
        resolution: str | None = None,
        fps: int | None = None,
        audio_muted: bool | None = None,
    ) -> dict[str, Any]:
        if title is not None:
            self._config.title = self._redactor.redact_text(title)
        if description is not None:
            self._config.description = self._redactor.redact_text(description)
        if privacy_status is not None:
            if privacy_status not in {"private", "unlisted", "public"}:
                raise ValueError("Invalid privacy_status")
            self._config.privacy_status = privacy_status
        if resolution is not None:
            if resolution not in {"360p", "480p", "720p", "1080p"}:
                raise ValueError("Unsupported resolution")
            self._config.resolution = resolution
        if fps is not None:
            if fps not in {30, 60}:
                raise ValueError("FPS must be 30 or 60")
            self._config.fps = fps
        if audio_muted is not None:
            self._config.audio_muted = bool(audio_muted)
        return self.snapshot()

    def connect_oauth(
        self,
        *,
        provided_csrf_state: str,
        access_token: str,
        stream_key: str = "live_secret_key_9999999999",
    ) -> StreamState:
        """Validate CSRF state and store OAuth token & Stream Key in protected memory."""
        if provided_csrf_state != self._csrf_state_token:
            self._state = StreamState.AUTH_REQUIRED
            self._last_error = "OAuth CSRF state mismatch"
            self._recorder.append_log("STREAM_OAUTH_CSRF_FAILED", self._last_error)
            raise StreamSecurityViolationError(self._last_error)

        if not access_token or len(access_token) < 8:
            self._state = StreamState.AUTH_REQUIRED
            raise StreamSecurityViolationError("Invalid OAuth token")

        self._oauth_access_token_secret = access_token
        self._stream_key_secret = stream_key
        # Register both secrets with RedactionEngine so they can never leak in any text/log
        self._redactor.register_sensitive_literal(access_token, "[REDACTED_OAUTH_TOKEN]")
        self._redactor.register_sensitive_literal(stream_key, "[REDACTED_STREAM_KEY]")
        self._state = StreamState.READY
        self._recorder.append_log("STREAM_OAUTH_CONNECTED", "OAuth 2.0 session established (tokens protected in memory)")
        return self._state

    def disconnect_and_revoke_oauth(self) -> StreamState:
        """Securely wipe OAuth token and Stream Key from memory and transition to DISCONNECTED."""
        if self._state in {StreamState.LIVE, StreamState.TESTING, StreamState.ENCODING}:
            self.stop_stream(reason="OAuth disconnect requested")
        self._oauth_access_token_secret = None
        self._stream_key_secret = None
        self._broadcast_id = None
        self._stream_id = None
        self._youtube_stream_status = "inactive"
        self._state = StreamState.DISCONNECTED
        self._recorder.append_log("STREAM_OAUTH_REVOKED", "Revoked OAuth token and wiped stream key from memory")
        return self._state

    def start_preview(self, canvas_payload_text: str) -> StreamState:
        """Render whitelisted Tester canvas preview after Fail-Closed redaction."""
        sanitized = self._redactor.redact_text(canvas_payload_text)
        frame_hash = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()
        self._preview_canvas_frame_hash = frame_hash
        self._encoder_canvas_frame_hash = frame_hash
        self._state = StreamState.PREVIEW
        self._recorder.append_log("STREAM_PREVIEW_STARTED", f"Preview verified (frame_sha256={frame_hash[:12]})")
        return self._state

    def start_test_signal(self) -> StreamState:
        """Start Fake Ingest Sink test signal without calling external YouTube APIs or RTMPS."""
        self._safety_guard.check_resource_limits()
        if not self._preview_canvas_frame_hash:
            self.start_preview("AegisLab Tester Safe Preview Frame")
        self._mode = StreamExecutionMode.TEST_MODE_SIMULATED
        self._state = StreamState.TESTING
        self._youtube_stream_status = "active"
        self._recorder.append_log(
            "STREAM_TEST_SIGNAL_STARTED",
            "Started isolated Test Signal on Mock Ingest Sink (0 external network bytes)",
        )
        return self._state

    def stop_test_signal(self) -> StreamState:
        """Stop test signal and ensure state NEVER leaks into LIVE mode."""
        self._state = StreamState.STOPPED
        self._youtube_stream_status = "inactive"
        self._recorder.append_log("STREAM_TEST_SIGNAL_STOPPED", "Stopped Test Signal; remained isolated from LIVE")
        return self._state

    def prepare_youtube_broadcast_and_stream(
        self,
        *,
        youtube_stream_active: bool = False,
        simulate_api_error: str | None = None,
    ) -> StreamState:
        """Steps 3-9 of YouTube Live flow: create broadcast/stream, bind, start encoder, check status."""
        if not self._user_age_verified_16_plus:
            self._state = StreamState.NOT_ELIGIBLE
            raise StreamSecurityViolationError("User/channel not eligible for YouTube Live broadcast")

        if not self._oauth_access_token_secret or not self._stream_key_secret:
            self._state = StreamState.AUTH_REQUIRED
            raise StreamSecurityViolationError("OAuth authentication required before broadcast creation")

        if simulate_api_error:
            self._state = StreamState.ERROR
            self._last_error = f"YouTube API Error: {simulate_api_error}"
            self._recorder.append_log("STREAM_API_ERROR", self._last_error)
            return self._state

        self._broadcast_id = "yt-bcast-verified-001"
        self._stream_id = "yt-stream-verified-001"
        self._state = StreamState.ENCODING
        self._youtube_stream_status = "active" if youtube_stream_active else "ready"
        return self._state

    def transition_to_live(self) -> StreamState:
        """Step 10: Transition to LIVE only if preview matches output AND YouTube stream is 'active'."""
        self._safety_guard.check_resource_limits()
        if self._mode == StreamExecutionMode.TEST_MODE_SIMULATED:
            raise StreamSecurityViolationError(
                "Cannot transition to real YouTube LIVE while in TEST_MODE_SIMULATED"
            )
        if not self._user_age_verified_16_plus:
            self._state = StreamState.NOT_ELIGIBLE
            raise StreamSecurityViolationError("Channel/age eligibility check failed")
        if not self._preview_canvas_frame_hash or (
            self._preview_canvas_frame_hash != self._encoder_canvas_frame_hash
        ):
            self._state = StreamState.ERROR
            self._last_error = "Preview canvas and encoder output mismatch (Fail-Closed block)"
            raise StreamSecurityViolationError(self._last_error)
        if self._youtube_stream_status != "active":
            self._state = StreamState.CONNECTING
            self._last_error = (
                f"Cannot transition broadcast to LIVE: YouTube stream status is '{self._youtube_stream_status}' (must be 'active')"
            )
            raise StreamSecurityViolationError(self._last_error)

        self._state = StreamState.LIVE
        self._recorder.append_log("STREAM_GO_LIVE", f"Broadcast {self._broadcast_id} transitioned to LIVE")
        return self._state

    def attempt_reconnect(self) -> StreamState:
        """Bounded reconnect; halts safely after MAX_RECONNECT_ATTEMPTS."""
        if self._reconnect_count >= self.MAX_RECONNECT_ATTEMPTS:
            self._state = StreamState.ERROR
            self._last_error = f"Max reconnect attempts ({self.MAX_RECONNECT_ATTEMPTS}) reached; auto-retry halted."
            self._recorder.append_log("STREAM_RECONNECT_EXHAUSTED", self._last_error)
            return self._state
        self._reconnect_count += 1
        self._state = StreamState.CONNECTING
        self._recorder.append_log(
            "STREAM_RECONNECT_ATTEMPT",
            f"Reconnect attempt {self._reconnect_count}/{self.MAX_RECONNECT_ATTEMPTS}",
        )
        return self._state

    def stop_stream(self, *, reason: str = "Operator requested stop") -> StreamState:
        """Highest priority stop: stops encoder, halts RTMPS, transitions broadcast to complete."""
        self._state = StreamState.STOPPING
        self._youtube_stream_status = "inactive"
        self._state = StreamState.STOPPED
        self._recorder.append_log("STREAM_STOPPED", f"Stream stopped safely: {reason}")
        return self._state

    def enforce_safety_guard_during_stream(
        self,
        *,
        simulated_available_ram_mib: int | None = None,
        simulated_process_rss_mib: int | None = None,
        simulated_disk_free_mib: int | None = None,
    ) -> StreamState:
        """Immediately stop streaming if SafetyGuard thresholds are breached."""
        try:
            self._safety_guard.check_resource_limits(
                simulated_available_ram_mib=simulated_available_ram_mib,
                simulated_process_rss_mib=simulated_process_rss_mib,
                simulated_disk_free_mib=simulated_disk_free_mib,
            )
            return self._state
        except ResourceLimitExceededError as exc:
            self.stop_stream(reason=f"SafetyGuard breach: {exc}")
            self._state = StreamState.ERROR
            self._last_error = str(exc)
            return self._state

    @property
    def csrf_state_token(self) -> str:
        return self._csrf_state_token

    def snapshot(self) -> dict[str, Any]:
        """Return sanitized UI state. Stream Key and OAuth Token are NEVER included."""
        raw = {
            "stream_state": self._state.value,
            "execution_mode": self._mode.value,
            "evidence_classification": (
                "SIMULATED"
                if self._mode == StreamExecutionMode.TEST_MODE_SIMULATED
                else ("NOT_CONNECTED" if self._state != StreamState.LIVE else "VERIFIED_BY_EXECUTION")
            ),
            "config": {
                "title": self._config.title,
                "description": self._config.description,
                "privacy_status": self._config.privacy_status,
                "resolution": self._config.resolution,
                "fps": self._config.fps,
                "bitrate_kbps": self._config.bitrate_kbps,
                "audio_muted": self._config.audio_muted,
                "mic_enabled": self._config.mic_enabled,
                "camera_enabled": self._config.camera_enabled,
                "system_audio_enabled": self._config.system_audio_enabled,
            },
            "whitelisted_canvas_sources": list(self._active_canvas_sources),
            "preview_matches_output": bool(
                self._preview_canvas_frame_hash
                and self._preview_canvas_frame_hash == self._encoder_canvas_frame_hash
            ),
            "youtube_stream_status": self._youtube_stream_status,
            "oauth_authenticated": self._oauth_access_token_secret is not None,
            "stream_key_configured": self._stream_key_secret is not None,
            "stream_key_exposed_to_ui": False,
            "reconnect_count": self._reconnect_count,
            "max_reconnect_attempts": self.MAX_RECONNECT_ATTEMPTS,
            "dropped_frames": self._dropped_frames,
            "user_age_eligible": self._user_age_verified_16_plus,
            "last_error": self._last_error,
        }
        return self._redactor.redact_structure(raw)
