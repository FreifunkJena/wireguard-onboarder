"""WireGuard conf file parse/upsert/remove and live sync."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path


_PUBLIC_KEY_RE = re.compile(r"^\s*PublicKey\s*=\s*(.+?)\s*$", re.IGNORECASE)
_ALLOWED_IPS_RE = re.compile(r"^\s*AllowedIPs\s*=\s*(.+?)\s*$", re.IGNORECASE)
_SECTION_RE = re.compile(r"^\s*\[(.+?)\]\s*$")


class WgConfError(RuntimeError):
    """WireGuard configuration or sync failure."""


@dataclass
class PeerBlock:
    public_key: str | None = None
    allowed_ips: list[str] = field(default_factory=list)
    start: int = 0
    end: int = 0  # exclusive line index
    lines: list[str] = field(default_factory=list)


def _networks_overlap(a: str, b: str) -> bool:
    try:
        net_a = ipaddress.ip_network(a, strict=False)
        net_b = ipaddress.ip_network(b, strict=False)
    except ValueError:
        return a == b
    return net_a.overlaps(net_b)


class WgConf:
    def __init__(
        self,
        config_path: Path,
        interface: str,
        *,
        sync: bool = True,
    ) -> None:
        self.config_path = config_path
        self.interface = interface
        self.sync = sync
        self._lock = threading.Lock()

    def _read_lines(self) -> list[str]:
        if not self.config_path.is_file():
            raise WgConfError(f"wireguard config missing: {self.config_path}")
        return self.config_path.read_text(encoding="utf-8").splitlines(keepends=True)

    def _write_lines(self, lines: list[str]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        text = "".join(lines)
        if text and not text.endswith("\n"):
            text += "\n"
        tmp = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(self.config_path)

    def _parse_peers(self, lines: list[str]) -> list[PeerBlock]:
        peers: list[PeerBlock] = []
        current: PeerBlock | None = None
        for index, line in enumerate(lines):
            section = _SECTION_RE.match(line)
            if section:
                if current is not None:
                    current.end = index
                    peers.append(current)
                    current = None
                name = section.group(1).strip().lower()
                if name == "peer":
                    current = PeerBlock(start=index, lines=[line])
                continue
            if current is not None:
                current.lines.append(line)
                key_match = _PUBLIC_KEY_RE.match(line)
                if key_match:
                    current.public_key = key_match.group(1).strip()
                ips_match = _ALLOWED_IPS_RE.match(line)
                if ips_match:
                    current.allowed_ips = [
                        part.strip()
                        for part in ips_match.group(1).split(",")
                        if part.strip()
                    ]
        if current is not None:
            current.end = len(lines)
            peers.append(current)
        return peers

    def find_peer_by_key(self, public_key: str) -> PeerBlock | None:
        with self._lock:
            lines = self._read_lines()
            for peer in self._parse_peers(lines):
                if peer.public_key == public_key:
                    return peer
            return None

    def find_conflicting_address(
        self, allowed_ips: str, exclude_public_key: str | None = None
    ) -> str | None:
        """Return public key of a peer whose AllowedIPs overlap, else None."""
        with self._lock:
            lines = self._read_lines()
            for peer in self._parse_peers(lines):
                if exclude_public_key and peer.public_key == exclude_public_key:
                    continue
                for existing in peer.allowed_ips:
                    if _networks_overlap(existing, allowed_ips):
                        return peer.public_key
            return None

    def used_allowed_ips(
        self, exclude_public_key: str | None = None
    ) -> set[str]:
        """All AllowedIPs entries currently present in the conf."""
        with self._lock:
            lines = self._read_lines()
            used: set[str] = set()
            for peer in self._parse_peers(lines):
                if exclude_public_key and peer.public_key == exclude_public_key:
                    continue
                used.update(peer.allowed_ips)
            return used

    def upsert_peer(
        self,
        public_key: str,
        allowed_ips: str,
        comment: str | None = None,
    ) -> bool:
        """Insert or update a peer. Returns True if created, False if updated."""
        with self._lock:
            lines = self._read_lines()
            peers = self._parse_peers(lines)
            existing = next(
                (peer for peer in peers if peer.public_key == public_key), None
            )
            block_lines = self._format_peer_block(
                public_key, allowed_ips, comment
            )
            if existing is None:
                if lines and not lines[-1].endswith("\n"):
                    lines[-1] = lines[-1] + "\n"
                if lines and lines[-1].strip() != "":
                    lines.append("\n")
                lines.extend(block_lines)
                self._write_lines(lines)
                self._syncconf_unlocked()
                return True

            new_lines = lines[: existing.start] + block_lines + lines[existing.end :]
            self._write_lines(new_lines)
            self._syncconf_unlocked()
            return False

    def remove_peer(self, public_key: str) -> bool:
        with self._lock:
            lines = self._read_lines()
            peers = self._parse_peers(lines)
            existing = next(
                (peer for peer in peers if peer.public_key == public_key), None
            )
            if existing is None:
                return False
            new_lines = lines[: existing.start] + lines[existing.end :]
            # Drop trailing blank lines left by removal noise carefully: keep file tidy.
            while new_lines and new_lines[-1].strip() == "":
                new_lines.pop()
            if new_lines:
                last = new_lines[-1]
                if not last.endswith("\n"):
                    new_lines[-1] = last + "\n"
            self._write_lines(new_lines)
            self._syncconf_unlocked()
            return True

    def _format_peer_block(
        self,
        public_key: str,
        allowed_ips: str,
        comment: str | None,
    ) -> list[str]:
        lines: list[str] = []
        lines.append("# freifunk-jena-wireguard-onboarder-managed\n")
        if comment:
            lines.append(f"# {comment}\n")
        lines.append("[Peer]\n")
        lines.append(f"PublicKey = {public_key}\n")
        lines.append(f"AllowedIPs = {allowed_ips}\n")
        return lines

    def _syncconf_unlocked(self) -> None:
        if not self.sync:
            return
        try:
            strip = subprocess.run(
                ["wg-quick", "strip", self.interface],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["wg", "syncconf", self.interface, "/dev/stdin"],
                input=strip.stdout,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise WgConfError("wg or wg-quick not found") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip()
            raise WgConfError(f"wg syncconf failed: {detail}") from exc

    def latest_handshakes(self) -> dict[str, int]:
        """Map public_key -> latest-handshake unix timestamp via `wg show dump`."""
        try:
            completed = subprocess.run(
                ["wg", "show", self.interface, "dump"],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise WgConfError("wg not found") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip()
            raise WgConfError(f"wg show dump failed: {detail}") from exc

        handshakes: dict[str, int] = {}
        lines = completed.stdout.splitlines()
        # First line is interface; subsequent lines are peers:
        # public_key psk endpoint allowed_ips latest_handshake ...
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            public_key = parts[0]
            try:
                handshakes[public_key] = int(parts[4])
            except ValueError:
                handshakes[public_key] = 0
        return handshakes
