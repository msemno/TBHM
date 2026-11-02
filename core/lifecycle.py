"""Internal phase-stop control flow, distinct from a recoverable probe error."""
from __future__ import annotations
import time


class PhaseStopped(BaseException):
    # Legacy adapters often catch Exception and continue probing. A deadline or
    # operator cancellation must reach the orchestrator instead of being retried.
    def __init__(self, state, reason):
        self.state = state
        self.reason = reason
        super().__init__(reason)


def check(owner):
    if not getattr(owner, '_phase_lifecycle_active', False):
        return
    runner = getattr(owner, 'runner', owner)
    event = getattr(runner, '_cancel_event', None)
    if event is not None and event.is_set():
        raise PhaseStopped('CANCELLED', 'operator cancellation requested')
    deadline = getattr(owner, '_phase_deadline', None)
    if deadline is not None and time.monotonic() >= deadline:
        raise PhaseStopped('TIMED_OUT', 'phase execution deadline reached')
