"""Persistent state for onboarder-managed WireGuard peers."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class ManagedPeer:
    public_key: str
    innercity_allowed_ips: str
    wan_allowed_ips: str
    registered_at: float
    comment: str | None = None

    @property
    def allowed_ips(self) -> str:
        """Backward-compatible alias for innercity AllowedIPs."""
        return self.innercity_allowed_ips


class PeerState:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._peers: dict[str, ManagedPeer] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        peers = raw.get("peers", {}) if isinstance(raw, dict) else {}
        if not isinstance(peers, dict):
            return
        for key, value in peers.items():
            if not isinstance(value, dict):
                continue
            try:
                inner = value.get("innercity_allowed_ips") or value.get(
                    "allowed_ips"
                )
                wan = value.get("wan_allowed_ips", "")
                if not inner:
                    continue
                self._peers[str(key)] = ManagedPeer(
                    public_key=str(value.get("public_key", key)),
                    innercity_allowed_ips=str(inner),
                    wan_allowed_ips=str(wan) if wan else "",
                    registered_at=float(value["registered_at"]),
                    comment=value.get("comment"),
                )
            except (KeyError, TypeError, ValueError):
                continue

    def _save_unlocked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "peers": {
                key: asdict(peer) for key, peer in sorted(self._peers.items())
            }
        }
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        tmp.replace(self._path)

    def get(self, public_key: str) -> ManagedPeer | None:
        with self._lock:
            return self._peers.get(public_key)

    def all_peers(self) -> list[ManagedPeer]:
        with self._lock:
            return list(self._peers.values())

    def find_by_innercity_allowed_ips(
        self, allowed_ips: str
    ) -> ManagedPeer | None:
        with self._lock:
            for peer in self._peers.values():
                if peer.innercity_allowed_ips == allowed_ips:
                    return peer
            return None

    def find_by_allowed_ips(self, allowed_ips: str) -> ManagedPeer | None:
        return self.find_by_innercity_allowed_ips(allowed_ips)

    def wan_used_ips(self, exclude_public_key: str | None = None) -> set[str]:
        with self._lock:
            used: set[str] = set()
            for key, peer in self._peers.items():
                if exclude_public_key and key == exclude_public_key:
                    continue
                if peer.wan_allowed_ips:
                    used.add(peer.wan_allowed_ips)
            return used

    def upsert(
        self,
        public_key: str,
        innercity_allowed_ips: str,
        wan_allowed_ips: str,
        comment: str | None = None,
        registered_at: float | None = None,
    ) -> ManagedPeer:
        with self._lock:
            peer = ManagedPeer(
                public_key=public_key,
                innercity_allowed_ips=innercity_allowed_ips,
                wan_allowed_ips=wan_allowed_ips,
                registered_at=(
                    time.time() if registered_at is None else registered_at
                ),
                comment=comment,
            )
            self._peers[public_key] = peer
            self._save_unlocked()
            return peer

    def remove(self, public_key: str) -> bool:
        with self._lock:
            if public_key not in self._peers:
                return False
            del self._peers[public_key]
            self._save_unlocked()
            return True
