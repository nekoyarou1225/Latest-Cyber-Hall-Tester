"""Bounded-time callback invocation helper.

Purpose: callbacks into the data plane / audio engine must never be waited on
without a deadline, and must never be awaited while holding a state lock.

Semantics (deliberately conservative):
- The callable runs in a daemon thread; the caller waits at most ``timeout_sec``.
- A callable that finishes after the deadline is reported as TIMEOUT. Its late
  result is discarded and can NEVER be used to claim success retroactively.
- Exceptions are reported as EXCEPTION (type name only, no message, so that
  nothing sensitive can leak into audit records).
- A hung callable keeps its daemon thread until it returns; this is an accepted,
  documented cost of not being able to kill Python threads safely.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import threading
from typing import Any, Callable


class CallStatus(str, Enum):
    OK = "OK"
    EXCEPTION = "EXCEPTION"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class BoundedResult:
    status: CallStatus
    value: Any = None
    error_type: str | None = None


def bounded_call(fn: Callable[..., Any], *args: Any, timeout_sec: float) -> BoundedResult:
    if (
        isinstance(timeout_sec, bool)
        or not isinstance(timeout_sec, (int, float))
        or not math.isfinite(float(timeout_sec))
        or not (0.0 < float(timeout_sec) <= 60.0)
    ):
        raise ValueError(f"timeout_sec must be a finite number in (0, 60], got {timeout_sec!r}")
    if not callable(fn):
        raise TypeError("fn must be callable")

    box: dict[str, Any] = {}
    done = threading.Event()

    def _runner() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - boundary: report, never propagate
            box["error"] = type(exc).__name__
        finally:
            done.set()

    worker = threading.Thread(target=_runner, name="aegislab-bounded-call", daemon=True)
    worker.start()
    if not done.wait(float(timeout_sec)):
        return BoundedResult(CallStatus.TIMEOUT)
    if "error" in box:
        return BoundedResult(CallStatus.EXCEPTION, error_type=box["error"])
    return BoundedResult(CallStatus.OK, value=box.get("value"))
