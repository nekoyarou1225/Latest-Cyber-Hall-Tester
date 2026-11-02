"""Privacy Protection & Redaction Engine (Module 18).

Enforces:
- Zero hardcoded real environment usernames, hostnames, IPs, or secrets in code.
- Dynamic in-memory detection of runtime environment identifiers alongside
  deterministic pattern rules across 14 sensitive categories.
- Fail-Closed behavior: if redaction fails, encounters an uninspected source,
  or post-redaction verification detects residual sensitive tokens, public output
  is rejected completely (RedactionFailClosedError).
- Explicit limitation disclosure: pattern-based redaction and synthetic unit tests
  do NOT guarantee 100% detection of arbitrary unknown free-text PII or text
  rasterized inside images/video.
"""

from __future__ import annotations

from dataclasses import dataclass
import getpass
import pathlib
import re
import socket
from typing import Any, Callable


class RedactionFailClosedError(RuntimeError):
    """Raised when redaction fails or an uninspected source is submitted for public output."""


REDACTION_LIMITATION_DISCLOSURE: str = (
    "KNOWN_PATTERN_AND_DICTIONARY_REDACTION_ONLY: Passing synthetic redaction tests "
    "verifies defined pattern rules and Fail-Closed blocking, but does NOT prove 100% "
    "detection of unknown free-text personal information or text embedded in raster images."
)

# Pre-compiled pattern rules for the 14 required inspection categories
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 _-]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 _-]+PRIVATE KEY-----"
)
_STREAM_URL_KEY_RE = re.compile(
    r"\b(rtmps?://[^\s/]+/[^\s/]+/)([^\s\"'<>]+)", re.IGNORECASE
)
_BEARER_OR_API_TOKEN_RE = re.compile(
    r"\b(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:AIza|ghp_|sk-|ya29\.)[A-Za-z0-9._~+/=-]{8,}|SYNTHETIC_[A-Z0-9_]*?(?:KEY|TOKEN|SECRET)[A-Z0-9_]*)\b"
)
_COOKIE_SESSION_RE = re.compile(
    r"(?i)\b(?:Cookie|Set-Cookie)\s*:\s*[^\r\n]+|\b(?:session_id|sid|csrftoken|jwt)=[A-Za-z0-9._~+/=-]{6,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_PASSWORD_ASSIGN_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|api_key|stream_key|access_token)\s*[:=]\s*([^\s,;\"']+)"
)
_AUTH_LOG_RE = re.compile(
    r"(?i)\b(?:pam_unix\([^\)]+\):[^\r\n]+|sudo:\s+[^\r\n]+|Accepted\s+(?:password|publickey)\s+for\s+[^\r\n]+)"
)
_MAC_ADDR_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
)
_IPV4_ADDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)
_IPV6_ADDR_RE = re.compile(
    r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b"
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_PHONE_RE = re.compile(
    r"(?:\+81[-\s]?|0)[0-9]{1,4}[-\s][0-9]{2,4}[-\s][0-9]{3,4}\b"
)
_SSID_RE = re.compile(
    r"(?i)\b(?:ssid|essid|bssid)\s*[:=]\s*([^\s,;\"']+)"
)
_INTERNAL_PATH_OR_URL_RE = re.compile(
    r"(?:file:///[^\s\"')\]>]+|/(?:home|root|etc)/[^\s\"')\]>:]+|https?://[^\s/\"')]+\.(?:internal|local|invalid)(?:/[^\s\"')]*)?)"
)


@dataclass(frozen=True)
class PreStreamSafetyVerdict:
    """7-item pre-stream safety checklist required by Section 11.3."""

    pii_protection_active: bool
    secret_inspection_passed: bool
    screen_capture_state: str
    audio_inputs_state: str
    allowed_sources: tuple[str, ...]
    uninspected_source_count: int
    streamable: bool
    block_reasons: tuple[str, ...]
    limitation_disclosure: str = REDACTION_LIMITATION_DISCLOSURE

    def to_dict(self) -> dict[str, Any]:
        return {
            "pii_protection_active": self.pii_protection_active,
            "secret_inspection_passed": self.secret_inspection_passed,
            "screen_capture_state": self.screen_capture_state,
            "audio_inputs_state": self.audio_inputs_state,
            "allowed_sources": list(self.allowed_sources),
            "uninspected_source_count": self.uninspected_source_count,
            "verdict": "STREAMABLE" if self.streamable else "BLOCKED",
            "streamable": self.streamable,
            "block_reasons": list(self.block_reasons),
            "limitation_disclosure": self.limitation_disclosure,
        }


class RedactionEngine:
    """Inspects and masks sensitive tokens across 14 categories with Fail-Closed guarantees."""

    def __init__(
        self,
        *,
        custom_sensitive_literals: dict[str, str] | None = None,
        include_runtime_env_tokens: bool = True,
        failure_injector: Callable[[], None] | None = None,
    ) -> None:
        self._failure_injector = failure_injector
        self._literal_map: dict[str, str] = {}

        if include_runtime_env_tokens:
            try:
                home_str = str(pathlib.Path.home())
                if home_str and home_str != "/":
                    self._literal_map[home_str] = "[REDACTED_PATH]"
            except Exception:
                pass
            try:
                user_str = getpass.getuser()
                if user_str and len(user_str) >= 2:
                    self._literal_map[user_str] = "[REDACTED_USER]"
            except Exception:
                pass
            try:
                host_str = socket.gethostname()
                if host_str and len(host_str) >= 2:
                    self._literal_map[host_str] = "[REDACTED_HOST]"
            except Exception:
                pass

        if custom_sensitive_literals:
            for literal, replacement in custom_sensitive_literals.items():
                if literal:
                    self._literal_map[literal] = replacement

    def register_sensitive_literal(self, raw_token: str, placeholder: str) -> None:
        if raw_token:
            self._literal_map[raw_token] = placeholder

    def redact_text(self, text: str) -> str:
        """Mask all 14 sensitive categories or raise RedactionFailClosedError on failure."""
        if not isinstance(text, str):
            raise RedactionFailClosedError(
                f"Expected string for redaction, got {type(text).__name__}"
            )
        try:
            if self._failure_injector is not None:
                self._failure_injector()

            out = text
            # 1. Exact literal dictionary (longest match first)
            for raw_token in sorted(self._literal_map.keys(), key=len, reverse=True):
                out = out.replace(raw_token, self._literal_map[raw_token])

            # 2. Private keys
            out = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", out)
            # 3. Stream URLs with embedded stream keys
            out = _STREAM_URL_KEY_RE.sub(r"\1[REDACTED_STREAM_KEY]", out)
            # 4. Auth logs
            out = _AUTH_LOG_RE.sub("[REDACTED_AUTH_LOG]", out)
            # 5. Cookie / Session / JWT
            out = _COOKIE_SESSION_RE.sub("[REDACTED_SESSION]", out)
            # 6. Bearer & API tokens
            out = _BEARER_OR_API_TOKEN_RE.sub("[REDACTED_TOKEN]", out)
            # 7. Password / Secret / Key assignments
            out = _PASSWORD_ASSIGN_RE.sub(
                lambda m: m.group(0).split(m.group(1))[0] + "[REDACTED_SECRET]",
                out,
            )
            # 8. SSID / BSSID
            out = _SSID_RE.sub(
                lambda m: m.group(0).split(m.group(1))[0] + "[REDACTED_SSID]",
                out,
            )
            # 9. Internal file paths & URLs
            out = _INTERNAL_PATH_OR_URL_RE.sub("[REDACTED_PATH]", out)
            # 10. Email addresses
            out = _EMAIL_RE.sub("[REDACTED_EMAIL]", out)
            # 11. MAC addresses
            out = _MAC_ADDR_RE.sub("[REDACTED_MAC]", out)
            # 12. IPv6 addresses
            out = _IPV6_ADDR_RE.sub("[REDACTED_IPV6]", out)
            # 13. IPv4 addresses
            out = _IPV4_ADDR_RE.sub("[REDACTED_IPV4]", out)
            # 14. Phone numbers
            out = _PHONE_RE.sub("[REDACTED_PHONE]", out)

            # Post-condition self-check: ensure no registered literal remains
            for raw_token in self._literal_map:
                if raw_token in out:
                    raise RedactionFailClosedError(
                        "Residual sensitive literal detected after redaction pass"
                    )
            return out
        except RedactionFailClosedError:
            raise
        except Exception as exc:
            raise RedactionFailClosedError(
                f"Redaction engine encountered internal error and failed closed: {type(exc).__name__}"
            ) from exc

    def redact_structure(self, data: Any) -> Any:
        """Recursively redact a JSON-compatible structure; fail closed on any error."""
        if isinstance(data, str):
            return self.redact_text(data)
        if isinstance(data, dict):
            return {
                self.redact_text(str(k)): self.redact_structure(v)
                for k, v in data.items()
            }
        if isinstance(data, list):
            return [self.redact_structure(item) for item in data]
        if isinstance(data, tuple):
            return tuple(self.redact_structure(item) for item in data)
        if isinstance(data, (int, float, bool)) or data is None:
            return data
        raise RedactionFailClosedError(
            f"Unsupported type in public output structure: {type(data).__name__}"
        )

    def evaluate_prestream_safety(
        self,
        *,
        sources: list[dict[str, Any]],
        screen_capture_on: bool = False,
        mic_on: bool = False,
        desktop_audio_on: bool = False,
        phase2a_prohibition_active: bool = True,
    ) -> PreStreamSafetyVerdict:
        """Evaluate the 7-item pre-stream safety checklist (Fail-Closed)."""
        block_reasons: list[str] = []
        allowed_names: list[str] = []
        uninspected_count = 0
        secret_inspection_passed = True

        if phase2a_prohibition_active:
            block_reasons.append(
                "Live streaming and recording are prohibited by Phase 2A policy (NOT TESTED)"
            )

        for src in sources:
            src_name = str(src.get("id", "unknown_source"))
            inspected = bool(src.get("inspected", False))
            allowlisted = bool(src.get("allowlisted", False))
            raw_content = str(src.get("content", ""))

            if not inspected or not allowlisted:
                uninspected_count += 1
                block_reasons.append(
                    f"Source '{src_name}' is uninspected or not in allowlist"
                )
                continue

            try:
                redacted = self.redact_text(raw_content)
                if redacted != raw_content:
                    secret_inspection_passed = False
                    block_reasons.append(
                        f"Source '{src_name}' contained unredacted sensitive patterns"
                    )
                else:
                    allowed_names.append(src_name)
            except RedactionFailClosedError as exc:
                secret_inspection_passed = False
                block_reasons.append(f"Redaction error on '{src_name}': {exc}")

        if screen_capture_on:
            block_reasons.append("Screen capture is active without manual frame clearance")

        streamable = (
            not phase2a_prohibition_active
            and secret_inspection_passed
            and uninspected_count == 0
            and not screen_capture_on
            and len(block_reasons) == 0
        )

        return PreStreamSafetyVerdict(
            pii_protection_active=True,
            secret_inspection_passed=secret_inspection_passed,
            screen_capture_state="ON" if screen_capture_on else "OFF",
            audio_inputs_state=(
                f"mic={'ON' if mic_on else 'OFF'}, desktop_audio={'ON' if desktop_audio_on else 'OFF'}"
            ),
            allowed_sources=tuple(allowed_names),
            uninspected_source_count=uninspected_count,
            streamable=streamable,
            block_reasons=tuple(block_reasons),
        )
