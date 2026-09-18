"""Entry point for freifunk-jena-wireguard-onboarder."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from pathlib import Path

from .config import DEFAULT_CONFIG_PATH, load_config
from .ratelimit import RateLimiter
from .server import OnboarderApp, create_server
from .state import PeerState
from .watchdog import Watchdog
from .wgconf import WgConf


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="freifunk-jena-wireguard-onboarder",
        description=(
            "HTTP service to register LibreMesh WireGuard peers "
            "(innercity + WAN) and expire stale keys."
        ),
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"path to config.ini (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="do not run wg syncconf (useful for tests)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        logging.error("%s", exc)
        return 1

    state = PeerState(config.state_path)
    sync = not args.no_sync
    innercity = WgConf(
        config.innercity.config_path,
        config.innercity.interface,
        sync=sync,
    )
    wan = WgConf(
        config.wan.config_path,
        config.wan.interface,
        sync=sync,
    )
    app = OnboarderApp(
        config,
        innercity,
        wan,
        state,
        RateLimiter(config.rate_limit_seconds),
    )
    watchdog = Watchdog(
        [innercity, wan],
        state,
        peer_timeout_seconds=config.peer_timeout_seconds,
        check_interval_seconds=config.check_interval_seconds,
    )
    httpd = create_server(app)

    def _shutdown(signum: int, _frame: object) -> None:
        logging.info("received signal %s, shutting down", signum)
        watchdog.stop()
        httpd.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    watchdog.start()
    logging.info(
        "listening on %s:%s (innercity=%s wan=%s)",
        config.listen,
        config.port,
        config.innercity.interface,
        config.wan.interface,
    )
    try:
        httpd.serve_forever()
    finally:
        watchdog.stop()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
