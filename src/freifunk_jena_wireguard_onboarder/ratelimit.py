"""Per-IP rate limiting."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Allow at most one event per key within a fixed window."""

    def __init__(self, window_seconds: int) -> None:
        if window_seconds < 0:
            raise ValueError("window_seconds must be >= 0")
        self._window = window_seconds
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds).

        When allowed, records the attempt. When denied, does not update.
        """
        if self._window == 0:
            return True, 0

        current = time.monotonic() if now is None else now
        with self._lock:
            previous = self._last.get(key)
            if previous is not None:
                elapsed = current - previous
                if elapsed < self._window:
                    remaining = self._window - elapsed
                    retry_after = int(remaining) if remaining == int(remaining) else int(remaining) + 1
                    return False, max(1, retry_after)
            self._last[key] = current
            return True, 0
