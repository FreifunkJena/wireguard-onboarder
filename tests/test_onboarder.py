"""Unit tests for freifunk-jena-wireguard-onboarder."""

from __future__ import annotations

import base64
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from freifunk_jena_wireguard_onboarder.allocator import (
    PoolExhaustedError,
    allocate_next,
)
from freifunk_jena_wireguard_onboarder.config import load_config
from freifunk_jena_wireguard_onboarder.ratelimit import RateLimiter
from freifunk_jena_wireguard_onboarder.server import OnboarderApp
from freifunk_jena_wireguard_onboarder.state import PeerState
from freifunk_jena_wireguard_onboarder.validate import (
    ValidationError,
    normalize_allowed_ips,
    validate_address_in_policy,
    validate_public_key,
)
from freifunk_jena_wireguard_onboarder.watchdog import Watchdog
from freifunk_jena_wireguard_onboarder.wgconf import WgConf


def _valid_key(seed: bytes = b"\x01" * 32) -> str:
    return base64.b64encode(seed).decode("ascii")


def _write_dual_ini(
    root: Path, inner: Path, wan: Path, state: Path
) -> Path:
    ini = root / "config.ini"
    ini.write_text(
        "[server]\nlisten = 127.0.0.1\nport = 18080\nrate_limit_seconds = 300\n"
        "[wireguard.innercity]\ninterface = wg-innercity\n"
        f"config_path = {inner}\n"
        "allowed_cidr = 10.66.0.0/24\nreserved = 10.66.0.1\n"
        "[wireguard.wan]\ninterface = wg-wan\n"
        f"config_path = {wan}\n"
        "address_pool = 10.99.0.0/24\nreserved = 10.99.0.1\n"
        "[watchdog]\npeer_timeout_seconds = 600\ncheck_interval_seconds = 30\n"
        f"state_path = {state}\n",
        encoding="utf-8",
    )
    return ini


class ValidateTests(unittest.TestCase):
    def test_public_key_accept(self) -> None:
        key = _valid_key()
        self.assertEqual(validate_public_key(key), key)

    def test_public_key_reject_short(self) -> None:
        bad = base64.b64encode(b"short").decode("ascii")
        with self.assertRaises(ValidationError):
            validate_public_key(bad)

    def test_public_key_reject_garbage(self) -> None:
        with self.assertRaises(ValidationError):
            validate_public_key("not-base64!!!")

    def test_normalize_bare_ip(self) -> None:
        self.assertEqual(normalize_allowed_ips("10.66.0.12"), "10.66.0.12/32")

    def test_normalize_cidr(self) -> None:
        self.assertEqual(normalize_allowed_ips("10.66.0.0/24"), "10.66.0.0/24")

    def test_address_policy_allow(self) -> None:
        cidr = ipaddress.IPv4Network("10.66.0.0/24")
        reserved = frozenset({ipaddress.IPv4Address("10.66.0.1")})
        net = validate_address_in_policy("10.66.0.12/32", cidr, reserved)
        self.assertEqual(str(net), "10.66.0.12/32")

    def test_address_policy_deny_outside(self) -> None:
        cidr = ipaddress.IPv4Network("10.66.0.0/24")
        with self.assertRaises(ValidationError):
            validate_address_in_policy("10.0.0.1/32", cidr, frozenset())

    def test_address_policy_deny_reserved(self) -> None:
        cidr = ipaddress.IPv4Network("10.66.0.0/24")
        reserved = frozenset({ipaddress.IPv4Address("10.66.0.1")})
        with self.assertRaises(ValidationError):
            validate_address_in_policy("10.66.0.1/32", cidr, reserved)


class AllocatorTests(unittest.TestCase):
    def test_skips_used_and_reserved(self) -> None:
        pool = ipaddress.IPv4Network("10.99.0.0/24")
        reserved = frozenset({ipaddress.IPv4Address("10.99.0.1")})
        first = allocate_next(pool, set(), reserved)
        self.assertEqual(first, "10.99.0.2/32")
        second = allocate_next(pool, {first}, reserved)
        self.assertEqual(second, "10.99.0.3/32")

    def test_exhausted(self) -> None:
        pool = ipaddress.IPv4Network("10.99.0.0/30")
        reserved = frozenset(
            {
                ipaddress.IPv4Address("10.99.0.1"),
                ipaddress.IPv4Address("10.99.0.2"),
            }
        )
        with self.assertRaises(PoolExhaustedError):
            allocate_next(pool, set(), reserved)


class RateLimitTests(unittest.TestCase):
    def test_allows_then_blocks(self) -> None:
        limiter = RateLimiter(300)
        ok, _ = limiter.check("1.2.3.4", now=1000.0)
        self.assertTrue(ok)
        denied, retry = limiter.check("1.2.3.4", now=1100.0)
        self.assertFalse(denied)
        self.assertEqual(retry, 200)
        ok2, _ = limiter.check("1.2.3.4", now=1300.0)
        self.assertTrue(ok2)

    def test_different_ips_independent(self) -> None:
        limiter = RateLimiter(300)
        self.assertTrue(limiter.check("1.1.1.1", now=1.0)[0])
        self.assertTrue(limiter.check("2.2.2.2", now=1.0)[0])


class WgConfUpsertTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "wg0.conf"
        self.path.write_text(
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=\n"
            "Address = 10.66.0.1/24\nListenPort = 51820\n",
            encoding="utf-8",
        )
        self.wg = WgConf(self.path, "wg0", sync=False)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_create_and_upsert(self) -> None:
        key = _valid_key()
        created = self.wg.upsert_peer(key, "10.66.0.12/32", comment="node-a")
        self.assertTrue(created)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn(f"PublicKey = {key}", text)
        self.assertIn("AllowedIPs = 10.66.0.12/32", text)

        updated = self.wg.upsert_peer(key, "10.66.0.99/32")
        self.assertFalse(updated)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("AllowedIPs = 10.66.0.99/32", text)
        self.assertNotIn("AllowedIPs = 10.66.0.12/32", text)
        self.assertEqual(text.count("[Peer]"), 1)

    def test_address_conflict(self) -> None:
        k1 = _valid_key(b"\x01" * 32)
        k2 = _valid_key(b"\x02" * 32)
        self.wg.upsert_peer(k1, "10.66.0.12/32")
        conflict = self.wg.find_conflicting_address(
            "10.66.0.12/32", exclude_public_key=k2
        )
        self.assertEqual(conflict, k1)
        self.assertIsNone(
            self.wg.find_conflicting_address(
                "10.66.0.12/32", exclude_public_key=k1
            )
        )

    def test_remove_peer(self) -> None:
        key = _valid_key()
        self.wg.upsert_peer(key, "10.66.0.12/32")
        self.assertTrue(self.wg.remove_peer(key))
        self.assertNotIn(key, self.path.read_text(encoding="utf-8"))
        self.assertFalse(self.wg.remove_peer(key))


class RegisterAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.inner_path = root / "wg-innercity.conf"
        self.wan_path = root / "wg-wan.conf"
        for path, addr in (
            (self.inner_path, "10.66.0.1/24"),
            (self.wan_path, "10.99.0.1/24"),
        ):
            path.write_text(
                "[Interface]\n"
                "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=\n"
                f"Address = {addr}\n",
                encoding="utf-8",
            )
        ini = _write_dual_ini(
            root, self.inner_path, self.wan_path, root / "state.json"
        )
        self.config = load_config(ini)
        self.state = PeerState(self.config.state_path)
        self.inner = WgConf(self.inner_path, "wg-innercity", sync=False)
        self.wan = WgConf(self.wan_path, "wg-wan", sync=False)
        self.app = OnboarderApp(
            self.config,
            self.inner,
            self.wan,
            self.state,
            RateLimiter(300),
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_register_both_tunnels(self) -> None:
        k1 = _valid_key(b"\x11" * 32)
        status, body, _ = self.app.register(
            {"public_key": k1, "address": "10.66.0.12"}, "10.0.0.1"
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["status"], "created")
        self.assertEqual(body["innercity"]["allowed_ips"], "10.66.0.12/32")
        self.assertEqual(body["wan"]["allowed_ips"], "10.99.0.2/32")
        self.assertIn("10.66.0.12/32", self.inner_path.read_text(encoding="utf-8"))
        self.assertIn("10.99.0.2/32", self.wan_path.read_text(encoding="utf-8"))

        k2 = _valid_key(b"\x22" * 32)
        status2, err, _ = self.app.register(
            {"public_key": k2, "address": "10.66.0.12"}, "10.0.0.2"
        )
        self.assertEqual(status2, 409)
        self.assertIn("address", err["error"])

    def test_already_registered_same_key_and_ip(self) -> None:
        key = _valid_key(b"\x66" * 32)
        status, body, _ = self.app.register(
            {"public_key": key, "address": "10.66.0.12"}, "10.0.0.1"
        )
        self.assertEqual(status, 201)
        status2, body2, _ = self.app.register(
            {"public_key": key, "address": "10.66.0.12"}, "10.0.0.8"
        )
        self.assertEqual(status2, 208)
        self.assertEqual(body2["status"], "already_registered")
        self.assertEqual(body2["wan"]["allowed_ips"], body["wan"]["allowed_ips"])

    def test_upsert_keeps_wan_ip(self) -> None:
        key = _valid_key(b"\x33" * 32)
        _, first, _ = self.app.register(
            {"public_key": key, "address": "10.66.0.12"}, "10.0.0.1"
        )
        wan_ip = first["wan"]["allowed_ips"]
        status, body, _ = self.app.register(
            {"public_key": key, "address": "10.66.0.55"}, "10.0.0.9"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "updated")
        self.assertEqual(body["innercity"]["allowed_ips"], "10.66.0.55/32")
        self.assertEqual(body["wan"]["allowed_ips"], wan_ip)
        self.assertIn("10.66.0.55/32", self.inner_path.read_text(encoding="utf-8"))

    def test_wan_allocates_next(self) -> None:
        k1 = _valid_key(b"\x41" * 32)
        k2 = _valid_key(b"\x42" * 32)
        _, b1, _ = self.app.register(
            {"public_key": k1, "address": "10.66.0.12"}, "10.0.0.1"
        )
        _, b2, _ = self.app.register(
            {"public_key": k2, "address": "10.66.0.13"}, "10.0.0.2"
        )
        self.assertEqual(b1["wan"]["allowed_ips"], "10.99.0.2/32")
        self.assertEqual(b2["wan"]["allowed_ips"], "10.99.0.3/32")

    def test_rate_limit(self) -> None:
        key = _valid_key(b"\x44" * 32)
        status, _, _ = self.app.register(
            {"public_key": key, "address": "10.66.0.12"}, "9.9.9.9"
        )
        self.assertEqual(status, 201)
        status2, _, headers = self.app.register(
            {"public_key": key, "address": "10.66.0.13"}, "9.9.9.9"
        )
        self.assertEqual(status2, 429)
        self.assertIn("Retry-After", headers)


class WatchdogTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.inner_path = root / "wg-inner.conf"
        self.wan_path = root / "wg-wan.conf"
        for path in (self.inner_path, self.wan_path):
            path.write_text(
                "[Interface]\n"
                "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=\n",
                encoding="utf-8",
            )
        self.inner = WgConf(self.inner_path, "wg-innercity", sync=False)
        self.wan = WgConf(self.wan_path, "wg-wan", sync=False)
        self.state = PeerState(root / "state.json")
        self.key = _valid_key(b"\x55" * 32)
        self.inner.upsert_peer(self.key, "10.66.0.12/32")
        self.wan.upsert_peer(self.key, "10.99.0.2/32")
        self.state.upsert(
            self.key,
            "10.66.0.12/32",
            "10.99.0.2/32",
            registered_at=1000.0,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_remove_never_connected_after_timeout(self) -> None:
        wd = Watchdog(
            [self.inner, self.wan],
            self.state,
            peer_timeout_seconds=600,
            check_interval_seconds=30,
            time_fn=lambda: 1000.0 + 600.0,
        )
        with mock.patch.object(
            self.inner, "latest_handshakes", return_value={self.key: 0}
        ), mock.patch.object(
            self.wan, "latest_handshakes", return_value={self.key: 0}
        ):
            removed = wd.tick()
        self.assertEqual(removed, [self.key])
        self.assertIsNone(self.state.get(self.key))
        self.assertNotIn(self.key, self.inner_path.read_text(encoding="utf-8"))
        self.assertNotIn(self.key, self.wan_path.read_text(encoding="utf-8"))

    def test_keep_if_either_tunnel_recent(self) -> None:
        wd = Watchdog(
            [self.inner, self.wan],
            self.state,
            peer_timeout_seconds=600,
            check_interval_seconds=30,
            time_fn=lambda: 2000.0,
        )
        with mock.patch.object(
            self.inner, "latest_handshakes", return_value={self.key: 0}
        ), mock.patch.object(
            self.wan, "latest_handshakes", return_value={self.key: 1900}
        ):
            removed = wd.tick()
        self.assertEqual(removed, [])
        self.assertIsNotNone(self.state.get(self.key))

    def test_remove_stale_handshake(self) -> None:
        wd = Watchdog(
            [self.inner, self.wan],
            self.state,
            peer_timeout_seconds=600,
            check_interval_seconds=30,
            time_fn=lambda: 2000.0,
        )
        with mock.patch.object(
            self.inner, "latest_handshakes", return_value={self.key: 1000}
        ), mock.patch.object(
            self.wan, "latest_handshakes", return_value={self.key: 1100}
        ):
            removed = wd.tick()
        self.assertEqual(removed, [self.key])


class StatePersistenceTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            state = PeerState(path)
            key = _valid_key()
            state.upsert(
                key,
                "10.66.0.12/32",
                "10.99.0.2/32",
                comment="x",
                registered_at=42.0,
            )
            reloaded = PeerState(path)
            peer = reloaded.get(key)
            self.assertIsNotNone(peer)
            assert peer is not None
            self.assertEqual(peer.innercity_allowed_ips, "10.66.0.12/32")
            self.assertEqual(peer.wan_allowed_ips, "10.99.0.2/32")
            self.assertEqual(peer.registered_at, 42.0)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn(key, data["peers"])


if __name__ == "__main__":
    unittest.main()
