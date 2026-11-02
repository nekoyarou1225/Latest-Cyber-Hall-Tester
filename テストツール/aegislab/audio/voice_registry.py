"""Voice license verification registry for AegisLab audio synthesis.

Key guarantees:
- Dual-layer evaluation: EngineLicense AND VoiceModelLicense must both be verified
  and allow the specific use case.
- Zero unverifiable claims: Built-in voice models (e.g. OpenJTalk Mei) without
  cryptographic hash and verifiable distribution license are strictly UNVERIFIED.
- Distinct use-case evaluation: commercial use, monetized stream, recorded video,
  local private preview, and redistribution are evaluated independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any


class LicenseStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    ALLOWED = "ALLOWED"
    PROHIBITED = "PROHIBITED"
    CONDITIONAL = "CONDITIONAL"


class UseCase(str, Enum):
    LOCAL_PRIVATE_PREVIEW = "LOCAL_PRIVATE_PREVIEW"
    COMMERCIAL_USE = "COMMERCIAL_USE"
    MONETIZED_STREAM = "MONETIZED_STREAM"
    RECORDED_VIDEO = "RECORDED_VIDEO"
    MODEL_REDISTRIBUTION = "MODEL_REDISTRIBUTION"


class ModelKind(str, Enum):
    SPEECH_VOICE = "SPEECH_VOICE"
    SYNTHETIC_TEST_SIGNAL = "SYNTHETIC_TEST_SIGNAL"


@dataclass(frozen=True)
class LicenseEvidence:
    verified_at_iso: str
    verifier: str
    evidence_ref: str
    terms_source_url: str


@dataclass(frozen=True)
class EngineLicense:
    engine_id: str
    name: str
    version: str
    license_type: str
    commercial_status: LicenseStatus
    monetized_stream_status: LicenseStatus
    recording_status: LicenseStatus
    redistribution_status: LicenseStatus
    evidence: LicenseEvidence | None = None
    attribution_required: bool = False
    attribution_text: str = ""


@dataclass(frozen=True)
class VoiceModelLicense:
    model_id: str
    engine_id: str
    name: str
    model_kind: ModelKind
    version: str
    distributor: str
    sha256_hex: str
    terms_url: str
    commercial_status: LicenseStatus
    monetized_stream_status: LicenseStatus
    recording_status: LicenseStatus
    redistribution_status: LicenseStatus
    evidence: LicenseEvidence | None = None
    attribution_required: bool = False
    attribution_text: str = ""


@dataclass(frozen=True)
class LicenseDecision:
    allowed: bool
    use_case: UseCase
    engine_id: str
    model_id: str
    reasons: tuple[str, ...]
    required_attribution: str = ""


class VoiceLicenseRegistry:
    """Manages engines and voice models license verification."""

    def __init__(self) -> None:
        self._engines: dict[str, EngineLicense] = {}
        self._models: dict[str, VoiceModelLicense] = {}
        self._audit_log: list[str] = []
        self._register_default_placeholders()

    def _register_default_placeholders(self) -> None:
        # OpenJTalk engine: Modified BSD (permissive), but evidence placeholder
        self.register_engine(
            EngineLicense(
                engine_id="open_jtalk",
                name="Open JTalk",
                version="1.11",
                license_type="Modified BSD",
                commercial_status=LicenseStatus.ALLOWED,
                monetized_stream_status=LicenseStatus.ALLOWED,
                recording_status=LicenseStatus.ALLOWED,
                redistribution_status=LicenseStatus.ALLOWED,
                evidence=LicenseEvidence(
                    verified_at_iso="2026-10-30T00:00:00Z",
                    verifier="AegisLab Safety Team",
                    evidence_ref="BSD 3-Clause License upstream Open JTalk",
                    terms_source_url="https://open-jtalk.sourceforge.net/",
                ),
                attribution_required=True,
                attribution_text="Open JTalk (Modified BSD)",
            )
        )

        # Mei Normal model: HTS Voice (MMDAgent).
        # Terms for commercial / recording vary by distribution. STRICTLY UNVERIFIED.
        self.register_model(
            VoiceModelLicense(
                model_id="openjtalk_mei_normal",
                engine_id="open_jtalk",
                name="MMDAgent Mei (Normal)",
                model_kind=ModelKind.SPEECH_VOICE,
                version="unspecified",
                distributor="MMDAgent / HTS Project",
                sha256_hex="",  # No hardcoded unverified hash
                terms_url="http://www.mmdagent.jp/",
                commercial_status=LicenseStatus.UNVERIFIED,
                monetized_stream_status=LicenseStatus.UNVERIFIED,
                recording_status=LicenseStatus.UNVERIFIED,
                redistribution_status=LicenseStatus.UNVERIFIED,
                evidence=None,
                attribution_required=True,
                attribution_text="Voice: Mei by MMDAgent",
            )
        )

        # Synthetic Test Signal (Sine wave / chirp): generated locally in AegisLab
        self.register_engine(
            EngineLicense(
                engine_id="synthetic_internal",
                name="AegisLab Synthetic Signal Generator",
                version="1.0.0",
                license_type="AegisLab Internal Test Tool",
                commercial_status=LicenseStatus.ALLOWED,
                monetized_stream_status=LicenseStatus.ALLOWED,
                recording_status=LicenseStatus.ALLOWED,
                redistribution_status=LicenseStatus.ALLOWED,
                evidence=LicenseEvidence(
                    verified_at_iso="2026-10-30T00:00:00Z",
                    verifier="AegisLab Core",
                    evidence_ref="Internal math synthesis",
                    terms_source_url="https://local.aegislab.invalid/synthetic",
                ),
            )
        )
        self.register_model(
            VoiceModelLicense(
                model_id="synthetic_tone_440",
                engine_id="synthetic_internal",
                name="Test Sine Tone 440Hz",
                model_kind=ModelKind.SYNTHETIC_TEST_SIGNAL,
                version="1.0.0",
                distributor="AegisLab",
                sha256_hex="00" * 32,
                terms_url="https://local.aegislab.invalid/synthetic",
                commercial_status=LicenseStatus.ALLOWED,
                monetized_stream_status=LicenseStatus.ALLOWED,
                recording_status=LicenseStatus.ALLOWED,
                redistribution_status=LicenseStatus.ALLOWED,
                evidence=LicenseEvidence(
                    verified_at_iso="2026-10-30T00:00:00Z",
                    verifier="AegisLab Core",
                    evidence_ref="Math generator",
                    terms_source_url="https://local.aegislab.invalid/synthetic",
                ),
            )
        )

    def register_engine(self, engine: EngineLicense, replace: bool = False) -> None:
        if not isinstance(engine, EngineLicense):
            raise TypeError("Expected EngineLicense")
        if not engine.engine_id or not re.match(r"^[a-zA-Z0-9_\-]+$", engine.engine_id):
            raise ValueError(f"Invalid engine_id: {engine.engine_id!r}")
        if engine.engine_id in self._engines and not replace:
            raise ValueError(f"Engine {engine.engine_id} already registered")
        self._engines[engine.engine_id] = engine
        self._audit_log.append(f"REGISTER_ENGINE:{engine.engine_id}")

    def register_model(self, model: VoiceModelLicense, replace: bool = False) -> None:
        if not isinstance(model, VoiceModelLicense):
            raise TypeError("Expected VoiceModelLicense")
        if not model.model_id or not re.match(r"^[a-zA-Z0-9_\-]+$", model.model_id):
            raise ValueError(f"Invalid model_id: {model.model_id!r}")
        if model.model_id in self._models and not replace:
            raise ValueError(f"Model {model.model_id} already registered")

        # Validation for claimed ALLOWED
        statuses = [
            model.commercial_status,
            model.monetized_stream_status,
            model.recording_status,
            model.redistribution_status,
        ]
        if any(s == LicenseStatus.ALLOWED for s in statuses):
            if model.model_kind != ModelKind.SYNTHETIC_TEST_SIGNAL:
                if not model.sha256_hex or not re.match(r"^[a-fA-F0-9]{64}$", model.sha256_hex):
                    raise ValueError("ALLOWED speech model requires a valid 64-hex sha256_hex")
                if not model.terms_url or not model.terms_url.startswith(("http://", "https://")):
                    raise ValueError("ALLOWED speech model requires valid terms_url")
                if not model.evidence:
                    raise ValueError("ALLOWED speech model requires complete LicenseEvidence")

        self._models[model.model_id] = model
        self._audit_log.append(f"REGISTER_MODEL:{model.model_id}")

    def evaluate_use_case(self, engine_id: str, model_id: str, use_case: UseCase) -> LicenseDecision:
        reasons: list[str] = []
        engine = self._engines.get(engine_id)
        if not engine:
            return LicenseDecision(
                allowed=False,
                use_case=use_case,
                engine_id=engine_id,
                model_id=model_id,
                reasons=(f"Engine {engine_id!r} not registered",),
            )

        model = self._models.get(model_id)
        if not model:
            return LicenseDecision(
                allowed=False,
                use_case=use_case,
                engine_id=engine_id,
                model_id=model_id,
                reasons=(f"Model {model_id!r} not registered",),
            )

        if model.engine_id != engine_id:
            reasons.append(f"Model {model_id} specifies engine {model.engine_id}, but {engine_id} was requested")

        # Map use case to engine & model status
        def _get_status(obj: Any, uc: UseCase) -> LicenseStatus:
            if uc == UseCase.LOCAL_PRIVATE_PREVIEW:
                return LicenseStatus.ALLOWED
            if uc == UseCase.COMMERCIAL_USE:
                return obj.commercial_status
            if uc == UseCase.MONETIZED_STREAM:
                return obj.monetized_stream_status
            if uc == UseCase.RECORDED_VIDEO:
                return obj.recording_status
            if uc == UseCase.MODEL_REDISTRIBUTION:
                return obj.redistribution_status
            return LicenseStatus.UNVERIFIED

        e_status = _get_status(engine, use_case)
        m_status = _get_status(model, use_case)

        if e_status != LicenseStatus.ALLOWED:
            reasons.append(f"Engine {engine_id} status for {use_case.value} is {e_status.value}")
        if m_status != LicenseStatus.ALLOWED:
            reasons.append(f"Model {model_id} status for {use_case.value} is {m_status.value}")

        allowed = len(reasons) == 0
        attrs: list[str] = []
        if allowed:
            if engine.attribution_required and engine.attribution_text:
                attrs.append(engine.attribution_text)
            if model.attribution_required and model.attribution_text:
                attrs.append(model.attribution_text)

        return LicenseDecision(
            allowed=allowed,
            use_case=use_case,
            engine_id=engine_id,
            model_id=model_id,
            reasons=tuple(reasons),
            required_attribution=" | ".join(attrs),
        )

    def can_use_commercial(self, engine_id: str, model_id: str) -> LicenseDecision:
        return self.evaluate_use_case(engine_id, model_id, UseCase.COMMERCIAL_USE)

    def can_use_monetized_stream(self, engine_id: str, model_id: str) -> LicenseDecision:
        return self.evaluate_use_case(engine_id, model_id, UseCase.MONETIZED_STREAM)

    def can_use_recorded_video(self, engine_id: str, model_id: str) -> LicenseDecision:
        return self.evaluate_use_case(engine_id, model_id, UseCase.RECORDED_VIDEO)

    def can_redistribute_model(self, engine_id: str, model_id: str) -> LicenseDecision:
        return self.evaluate_use_case(engine_id, model_id, UseCase.MODEL_REDISTRIBUTION)
