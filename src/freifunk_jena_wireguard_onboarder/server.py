"""HTTP API for WireGuard peer registration."""

from __future__ import annotations

import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .allocator import PoolExhaustedError, allocate_next
from .config import Config
from .ratelimit import RateLimiter
from .state import PeerState
from .validate import (
    ValidationError,
    normalize_allowed_ips,
    sanitize_comment,
    validate_address_in_policy,
    validate_public_key,
)
from .wgconf import WgConf, WgConfError

logger = logging.getLogger(__name__)


class OnboarderApp:
    def __init__(
        self,
        config: Config,
        innercity: WgConf,
        wan: WgConf,
        state: PeerState,
        rate_limiter: RateLimiter,
    ) -> None:
        self.config = config
        self.innercity = innercity
        self.wan = wan
        self.state = state
        self.rate_limiter = rate_limiter

    def register(
        self, payload: dict[str, Any], client_ip: str
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        allowed, retry_after = self.rate_limiter.check(client_ip)
        if not allowed:
            return (
                429,
                {"error": "rate limit exceeded"},
                {"Retry-After": str(retry_after)},
            )

        try:
            public_key = validate_public_key(payload.get("public_key"))
            innercity_ips = normalize_allowed_ips(payload.get("address"))
            validate_address_in_policy(
                innercity_ips,
                self.config.innercity.cidr,
                self.config.innercity.reserved,
            )
            comment = sanitize_comment(payload.get("comment"))
        except ValidationError as exc:
            return 400, {"error": str(exc)}, {}

        existing = self.state.get(public_key)
        try:
            conflict = self.innercity.find_conflicting_address(
                innercity_ips, exclude_public_key=public_key
            )
        except WgConfError as exc:
            return 503, {"error": str(exc)}, {}
        if conflict is not None:
            return (
                409,
                {"error": "innercity address already registered to another peer"},
                {},
            )
        state_conflict = self.state.find_by_innercity_allowed_ips(innercity_ips)
        if state_conflict is not None and state_conflict.public_key != public_key:
            return (
                409,
                {"error": "innercity address already registered to another peer"},
                {},
            )

        if existing is not None and existing.wan_allowed_ips:
            wan_ips = existing.wan_allowed_ips
        else:
            try:
                used = self.wan.used_allowed_ips(exclude_public_key=public_key)
            except WgConfError as exc:
                return 503, {"error": str(exc)}, {}
            used |= self.state.wan_used_ips(exclude_public_key=public_key)
            try:
                wan_ips = allocate_next(
                    self.config.wan.cidr,
                    used,
                    self.config.wan.reserved,
                )
            except PoolExhaustedError as exc:
                return 503, {"error": str(exc)}, {}

        already_registered = (
            existing is not None
            and existing.innercity_allowed_ips == innercity_ips
            and existing.wan_allowed_ips == wan_ips
        )

        try:
            created_inner = self.innercity.upsert_peer(
                public_key, innercity_ips, comment
            )
            created_wan = self.wan.upsert_peer(public_key, wan_ips, comment)
            self.state.upsert(
                public_key,
                innercity_allowed_ips=innercity_ips,
                wan_allowed_ips=wan_ips,
                comment=comment,
                registered_at=time.time(),
            )
        except WgConfError as exc:
            logger.exception("register failed")
            return 503, {"error": str(exc)}, {}

        if already_registered:
            outcome = "already_registered"
            status = 208
        elif existing is None and (created_inner or created_wan):
            outcome = "created"
            status = 201
        else:
            outcome = "updated"
            status = 200

        body = {
            "status": outcome,
            "public_key": public_key,
            "innercity": {
                "interface": self.config.innercity.interface,
                "allowed_ips": innercity_ips,
            },
            "wan": {
                "interface": self.config.wan.interface,
                "allowed_ips": wan_ips,
            },
        }
        return status, body, {}

    def health(self) -> tuple[int, dict[str, Any], dict[str, str]]:
        return 200, {"ok": True}, {}

    def peers(self) -> tuple[int, dict[str, Any], dict[str, str]]:
        handshakes: dict[str, int] = {}
        for tunnel in (self.innercity, self.wan):
            try:
                for key, ts in tunnel.latest_handshakes().items():
                    handshakes[key] = max(handshakes.get(key, 0), ts)
            except WgConfError:
                continue
        now = time.time()
        items = []
        for peer in self.state.all_peers():
            handshake = handshakes.get(peer.public_key, 0)
            age = None if handshake <= 0 else max(0, int(now - handshake))
            items.append(
                {
                    "public_key": peer.public_key,
                    "innercity_allowed_ips": peer.innercity_allowed_ips,
                    "wan_allowed_ips": peer.wan_allowed_ips,
                    "registered_at": peer.registered_at,
                    "latest_handshake": handshake or None,
                    "handshake_age_seconds": age,
                    "comment": peer.comment,
                }
            )
        return 200, {"peers": items}, {}


def make_handler(app: OnboarderApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "FreifunkJenaWireguardOnboarder/0.1"

        def log_message(self, fmt: str, *args: object) -> None:
            logger.info("%s - %s", self.address_string(), fmt % args)

        def _client_ip(self) -> str:
            return self.client_address[0]

        def _send_json(
            self,
            status: int,
            body: dict[str, Any],
            headers: dict[str, str] | None = None,
        ) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if headers:
                for key, value in headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/health":
                status, body, headers = app.health()
                self._send_json(status, body, headers)
                return
            if path == "/peers":
                status, body, headers = app.peers()
                self._send_json(status, body, headers)
                return
            self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path != "/register":
                self._send_json(404, {"error": "not found"})
                return
            length_header = self.headers.get("Content-Length", "0")
            try:
                length = int(length_header)
            except ValueError:
                self._send_json(400, {"error": "invalid Content-Length"})
                return
            if length < 0 or length > 1_048_576:
                self._send_json(400, {"error": "request body too large"})
                return
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid JSON"})
                return
            if not isinstance(payload, dict):
                self._send_json(400, {"error": "JSON object required"})
                return
            status, body, headers = app.register(payload, self._client_ip())
            self._send_json(status, body, headers)

    return Handler


def create_server(app: OnboarderApp) -> ThreadingHTTPServer:
    handler = make_handler(app)
    return ThreadingHTTPServer((app.config.listen, app.config.port), handler)
