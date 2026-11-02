"""Speech request priority queue with strict capacity, TTL, and playback state machine.

Key requirements addressed:
- Injected monotonic clock (no wall-clock drift).
- Strict capacity, max text characters, and TTL validated at init and enqueue.
- Duplicate history cache capped by max entries and TTL.
- Complete playback state machine: IDLE -> DISPATCHED -> PLAYING <-> PAUSED -> IDLE / INTERRUPTED.
- Emergency interrupt and stop callbacks invoked outside lock via bounded_call.
- Distinguishes STOPPED from STOP_UNCONFIRMED.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from enum import Enum
import math
import re
import threading
import time
from typing import Any, Callable

from aegislab.core.bounded_call import bounded_call, CallStatus


class SpeechPriority(int, Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL_ALERT = 4


class SpeechCategory(str, Enum):
    SECURITY_ALERT = "SECURITY_ALERT"
    SIMULATION_EVENT = "SIMULATION_EVENT"
    METRIC_UPDATE = "METRIC_UPDATE"
    OPERATOR_NOTICE = "OPERATOR_NOTICE"


class PlaybackState(str, Enum):
    IDLE = "IDLE"
    DISPATCHED = "DISPATCHED"
    PLAYING = "PLAYING"
    PAUSED = "PAUSED"
    INTERRUPTED = "INTERRUPTED"


class PreemptOutcome(str, Enum):
    PREEMPT_CONFIRMED = "PREEMPT_CONFIRMED"
    UNCONFIRMED_NO_CALLBACK = "UNCONFIRMED_NO_CALLBACK"
    UNCONFIRMED_REFUSED = "UNCONFIRMED_REFUSED"
    UNCONFIRMED_EXCEPTION = "UNCONFIRMED_EXCEPTION"
    UNCONFIRMED_TIMEOUT = "UNCONFIRMED_TIMEOUT"


class StopOutcome(str, Enum):
    STOPPED = "STOPPED"
    STOP_UNCONFIRMED = "STOP_UNCONFIRMED"


@dataclass(frozen=True)
class SpeechItem:
    item_id: str
    text: str
    priority: SpeechPriority
    category: SpeechCategory
    enqueued_at: float
    ttl_sec: float
    engine_id: str
    model_id: str


@dataclass(frozen=True)
class EnqueueResult:
    accepted: bool
    reason: str
    item: SpeechItem | None = None


class SpeechQueue:
    def __init__(
        self,
        *,
        max_capacity: int = 50,
        max_text_chars: int = 500,
        default_ttl_sec: float = 60.0,
        duplicate_suppression_window_sec: float = 5.0,
        max_duplicate_cache_entries: int = 100,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if (
            isinstance(max_capacity, bool)
            or not isinstance(max_capacity, int)
            or not (1 <= max_capacity <= 1000)
        ):
            raise ValueError(f"max_capacity must be int in [1, 1000], got {max_capacity!r}")
        if (
            isinstance(max_text_chars, bool)
            or not isinstance(max_text_chars, int)
            or not (10 <= max_text_chars <= 10000)
        ):
            raise ValueError(f"max_text_chars must be int in [10, 10000], got {max_text_chars!r}")
        if (
            isinstance(default_ttl_sec, bool)
            or not isinstance(default_ttl_sec, (int, float))
            or not math.isfinite(float(default_ttl_sec))
            or not (0.1 <= float(default_ttl_sec) <= 3600.0)
        ):
            raise ValueError(f"default_ttl_sec must be in [0.1, 3600.0], got {default_ttl_sec!r}")

        self.max_capacity = max_capacity
        self.max_text_chars = max_text_chars
        self.default_ttl_sec = float(default_ttl_sec)
        self.duplicate_suppression_window_sec = float(duplicate_suppression_window_sec)
        self.max_duplicate_cache_entries = max_duplicate_cache_entries
        self._clock = clock if clock is not None else time.monotonic

        self._lock = threading.RLock()
        self._queue: list[SpeechItem] = []
        self._playback_state: PlaybackState = PlaybackState.IDLE
        self._current_item: SpeechItem | None = None
        self._duplicate_cache: OrderedDict[str, float] = OrderedDict()
        self._seq = 0
        self._audit_events: deque[str] = deque(maxlen=200)

    def _normalize_text(self, text: str) -> str:
        # Strip control characters, keep plain characters and space
        clean = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        return clean.strip()

    def enqueue(
        self,
        text: str,
        *,
        priority: SpeechPriority = SpeechPriority.NORMAL,
        category: SpeechCategory = SpeechCategory.OPERATOR_NOTICE,
        engine_id: str,
        model_id: str,
        ttl_sec: float | None = None,
    ) -> EnqueueResult:
        with self._lock:
            now = self._clock()
            self._purge_expired_locked(now)

            if not isinstance(text, str):
                return EnqueueResult(False, "text must be a str")
            norm_text = self._normalize_text(text)
            if not norm_text:
                return EnqueueResult(False, "text is empty after normalization")
            if len(norm_text) > self.max_text_chars:
                return EnqueueResult(False, f"text length {len(norm_text)} exceeds max {self.max_text_chars}")

            effective_ttl = self.default_ttl_sec if ttl_sec is None else float(ttl_sec)
            if effective_ttl <= 0:
                return EnqueueResult(False, "ttl_sec must be positive")

            # Check duplicate suppression
            if norm_text in self._duplicate_cache:
                last_seen = self._duplicate_cache[norm_text]
                if (now - last_seen) < self.duplicate_suppression_window_sec:
                    return EnqueueResult(False, "duplicate suppressed within window")

            if len(self._queue) >= self.max_capacity:
                return EnqueueResult(False, "queue capacity full")

            self._seq += 1
            item = SpeechItem(
                item_id=f"sp_{self._seq}_{int(now)}",
                text=norm_text,
                priority=priority,
                category=category,
                enqueued_at=now,
                ttl_sec=effective_ttl,
                engine_id=engine_id,
                model_id=model_id,
            )

            # Insert keeping priority order (higher priority first)
            inserted = False
            for idx, existing in enumerate(self._queue):
                if int(item.priority) > int(existing.priority):
                    self._queue.insert(idx, item)
                    inserted = True
                    break
            if not inserted:
                self._queue.append(item)

            # Record duplicate cache
            self._duplicate_cache[norm_text] = now
            if len(self._duplicate_cache) > self.max_duplicate_cache_entries:
                self._duplicate_cache.popitem(last=False)

            self._audit_events.append(f"ENQUEUE:{item.item_id}:{item.priority.name}")
            return EnqueueResult(True, "enqueued", item)

    def _purge_expired_locked(self, now: float) -> None:
        kept: list[SpeechItem] = []
        for it in self._queue:
            if (now - it.enqueued_at) <= it.ttl_sec:
                kept.append(it)
            else:
                self._audit_events.append(f"EXPIRED:{it.item_id}")
        self._queue = kept

    def get_next_item(self) -> SpeechItem | None:
        with self._lock:
            now = self._clock()
            self._purge_expired_locked(now)
            if not self._queue:
                return None
            item = self._queue.pop(0)
            self._current_item = item
            self._playback_state = PlaybackState.DISPATCHED
            self._audit_events.append(f"DISPATCH:{item.item_id}")
            return item

    def report_playback_started(self, item_id: str) -> None:
        with self._lock:
            if not self._current_item or self._current_item.item_id != item_id:
                raise ValueError(f"Cannot start playback: active item mismatch for {item_id}")
            if self._playback_state not in (PlaybackState.DISPATCHED, PlaybackState.PAUSED):
                raise ValueError(f"Cannot start playback from state {self._playback_state.name}")
            self._playback_state = PlaybackState.PLAYING
            self._audit_events.append(f"PLAYING:{item_id}")

    def report_playback_completed(self, item_id: str) -> None:
        with self._lock:
            if not self._current_item or self._current_item.item_id != item_id:
                raise ValueError(f"Cannot complete playback: item mismatch for {item_id}")
            self._playback_state = PlaybackState.IDLE
            self._current_item = None
            self._audit_events.append(f"COMPLETED:{item_id}")

    def emergency_interrupt(
        self,
        stop_active_cb: Callable[[], bool] | None = None,
        timeout_sec: float = 2.0,
    ) -> PreemptOutcome:
        """Interrupts current playback and discards queue."""
        with self._lock:
            self._queue.clear()
            active_item = self._current_item
            current_state = self._playback_state

        if active_item is None or current_state == PlaybackState.IDLE:
            with self._lock:
                self._playback_state = PlaybackState.IDLE
                self._current_item = None
            return PreemptOutcome.PREEMPT_CONFIRMED

        if stop_active_cb is None:
            with self._lock:
                self._playback_state = PlaybackState.INTERRUPTED
                self._audit_events.append(f"PREEMPT_NO_CB:{active_item.item_id}")
            return PreemptOutcome.UNCONFIRMED_NO_CALLBACK

        # Execute callback outside lock
        res = bounded_call(stop_active_cb, timeout_sec=timeout_sec)
        with self._lock:
            if res.status == CallStatus.OK:
                if res.value is True:
                    self._playback_state = PlaybackState.IDLE
                    self._current_item = None
                    self._audit_events.append(f"PREEMPT_CONFIRMED:{active_item.item_id}")
                    return PreemptOutcome.PREEMPT_CONFIRMED
                else:
                    self._playback_state = PlaybackState.INTERRUPTED
                    self._audit_events.append(f"PREEMPT_REFUSED:{active_item.item_id}")
                    return PreemptOutcome.UNCONFIRMED_REFUSED
            elif res.status == CallStatus.TIMEOUT:
                self._playback_state = PlaybackState.INTERRUPTED
                self._audit_events.append(f"PREEMPT_TIMEOUT:{active_item.item_id}")
                return PreemptOutcome.UNCONFIRMED_TIMEOUT
            else:
                self._playback_state = PlaybackState.INTERRUPTED
                self._audit_events.append(f"PREEMPT_EXCEPTION:{active_item.item_id}:{res.error_type}")
                return PreemptOutcome.UNCONFIRMED_EXCEPTION

    def stop_all(
        self,
        stop_active_cb: Callable[[], bool] | None = None,
        timeout_sec: float = 2.0,
    ) -> StopOutcome:
        outcome = self.emergency_interrupt(stop_active_cb, timeout_sec=timeout_sec)
        if outcome == PreemptOutcome.PREEMPT_CONFIRMED:
            return StopOutcome.STOPPED
        return StopOutcome.STOP_UNCONFIRMED

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            self._purge_expired_locked(now)
            return {
                "queue_length": len(self._queue),
                "playback_state": self._playback_state.value,
                "current_item_id": self._current_item.item_id if self._current_item else None,
                "cached_duplicates": len(self._duplicate_cache),
            }
