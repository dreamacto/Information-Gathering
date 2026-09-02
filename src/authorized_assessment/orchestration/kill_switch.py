"""Thread-safe local kill switch with child cancellation propagation."""
from __future__ import annotations
import threading
from dataclasses import dataclass

@dataclass(frozen=True)
class KillState:
    active: bool
    reason: str | None
    generation: int

class KillSwitch:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active = False
        self._reason: str | None = None
        self._generation = 0
        self._children: set[threading.Event] = set()

    def request(self, reason: str = "operator requested stop") -> KillState:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("kill switch reason is required")
        with self._lock:
            if not self._active:
                self._generation += 1
            self._active, self._reason = True, reason.strip()
            for event in tuple(self._children):
                event.set()
            return self.state()

    def clear(self) -> KillState:
        with self._lock:
            self._active, self._reason = False, None
            self._generation += 1
            return self.state()

    def is_set(self) -> bool:
        with self._lock:
            return self._active

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def state(self) -> KillState:
        return KillState(self._active, self._reason, self._generation)

    def child_event(self) -> threading.Event:
        event = threading.Event()
        with self._lock:
            self._children.add(event)
            if self._active:
                event.set()
        return event

    def release_child(self, event: threading.Event) -> None:
        with self._lock:
            self._children.discard(event)

    def guard(self) -> None:
        if self.is_set():
            raise RuntimeError("kill switch active")

KillToken = KillSwitch
__all__ = ["KillState", "KillSwitch", "KillToken"]
