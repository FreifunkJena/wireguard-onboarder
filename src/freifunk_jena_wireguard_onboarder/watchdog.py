"""Handshake watchdog that removes stale managed peers from both tunnels."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from .state import PeerState
from .wgconf import WgConf, WgConfError

logger = logging.getLogger(__name__)


class Watchdog:
    def __init__(
        self,
        tunnels: list[WgConf],
        state: PeerState,
        *,
        peer_timeout_seconds: int = 600,
        check_interval_seconds: int = 30,
        time_fn: Callable[[], float] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ) -> None:
        self._tunnels = tunnels
        self._state = state
        self._timeout = peer_timeout_seconds
        self._interval = check_interval_seconds
        self._time = time_fn or time.time
        self._sleep = sleep_fn or time.sleep
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="wg-onboarder-watchdog", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 — keep watchdog alive
                logger.exception("watchdog tick failed")
            self._stop.wait(self._interval)

    def _merged_handshakes(self) -> dict[str, int]:
        """Best (newest) handshake per public key across all tunnels."""
        merged: dict[str, int] = {}
        any_ok = False
        for tunnel in self._tunnels:
            try:
                for key, ts in tunnel.latest_handshakes().items():
                    merged[key] = max(merged.get(key, 0), ts)
                any_ok = True
            except WgConfError:
                logger.warning(
                    "could not read handshakes on %s", tunnel.interface
                )
        if not any_ok:
            logger.warning("could not read handshakes on any tunnel")
        return merged

    def tick(self) -> list[str]:
        """Expire stale peers. Returns list of removed public keys."""
        now = self._time()
        handshakes = self._merged_handshakes()

        removed: list[str] = []
        for peer in self._state.all_peers():
            handshake = handshakes.get(peer.public_key, 0)
            if handshake > 0:
                stale = (now - handshake) >= self._timeout
            else:
                stale = (now - peer.registered_at) >= self._timeout
            if not stale:
                continue
            remove_ok = True
            for tunnel in self._tunnels:
                try:
                    tunnel.remove_peer(peer.public_key)
                except WgConfError:
                    logger.exception(
                        "failed to remove stale peer %s from %s",
                        peer.public_key,
                        tunnel.interface,
                    )
                    remove_ok = False
            if not remove_ok:
                continue
            self._state.remove(peer.public_key)
            removed.append(peer.public_key)
            logger.info(
                "removed stale peer %s (innercity=%s wan=%s)",
                peer.public_key,
                peer.innercity_allowed_ips,
                peer.wan_allowed_ips,
            )
        return removed
