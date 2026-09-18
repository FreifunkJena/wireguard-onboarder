"""Load onboarder configuration from an INI file."""

from __future__ import annotations

import configparser
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_CONFIG_PATH = Path("/etc/freifunk-jena-wireguard-onboarder/config.ini")


@dataclass(frozen=True)
class TunnelConfig:
    """One WireGuard interface managed by the onboarder."""

    interface: str
    config_path: Path
    # Innercity: client IPs must be inside this CIDR.
    # WAN: server allocates from this pool (same field).
    cidr: ipaddress.IPv4Network
    reserved: frozenset[ipaddress.IPv4Address] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Config:
    listen: str = "0.0.0.0"
    port: int = 8080
    rate_limit_seconds: int = 300
    innercity: TunnelConfig = field(
        default_factory=lambda: TunnelConfig(
            interface="wg-innercity",
            config_path=Path("/etc/wireguard/wg-innercity.conf"),
            cidr=ipaddress.IPv4Network("10.66.0.0/24"),
            reserved=frozenset({ipaddress.IPv4Address("10.66.0.1")}),
        )
    )
    wan: TunnelConfig = field(
        default_factory=lambda: TunnelConfig(
            interface="wg-wan",
            config_path=Path("/etc/wireguard/wg-wan.conf"),
            cidr=ipaddress.IPv4Network("10.99.0.0/24"),
            reserved=frozenset({ipaddress.IPv4Address("10.99.0.1")}),
        )
    )
    peer_timeout_seconds: int = 600
    check_interval_seconds: int = 30
    state_path: Path = Path(
        "/var/lib/freifunk-jena-wireguard-onboarder/state.json"
    )


def _parse_reserved(raw: str) -> frozenset[ipaddress.IPv4Address]:
    addresses: set[ipaddress.IPv4Address] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        addresses.add(ipaddress.IPv4Address(part))
    return frozenset(addresses)


def _load_tunnel(
    parser: configparser.ConfigParser,
    section: str,
    *,
    default_interface: str,
    default_config_path: str,
    default_cidr: str,
    default_reserved: str,
    cidr_key: str,
) -> TunnelConfig:
    if not parser.has_section(section):
        raise ValueError(f"missing config section [{section}]")
    interface = parser.get(section, "interface", fallback=default_interface)
    config_path = Path(
        parser.get(section, "config_path", fallback=default_config_path)
    )
    cidr = ipaddress.IPv4Network(
        parser.get(section, cidr_key, fallback=default_cidr),
        strict=False,
    )
    reserved = _parse_reserved(
        parser.get(section, "reserved", fallback=default_reserved)
    )
    return TunnelConfig(
        interface=interface,
        config_path=config_path,
        cidr=cidr,
        reserved=reserved,
    )


def load_config(path: Path | str | None = None) -> Config:
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    parser = configparser.ConfigParser()
    if not config_path.is_file():
        raise FileNotFoundError(f"config not found: {config_path}")
    parser.read(config_path)

    listen = parser.get("server", "listen", fallback="0.0.0.0")
    port = parser.getint("server", "port", fallback=8080)
    rate_limit_seconds = parser.getint(
        "server", "rate_limit_seconds", fallback=300
    )

    # Prefer explicit dual-tunnel sections; fall back to legacy [wireguard]
    # as innercity and require [wireguard.wan].
    if parser.has_section("wireguard.innercity"):
        innercity = _load_tunnel(
            parser,
            "wireguard.innercity",
            default_interface="wg-innercity",
            default_config_path="/etc/wireguard/wg-innercity.conf",
            default_cidr="10.66.0.0/24",
            default_reserved="10.66.0.1",
            cidr_key="allowed_cidr",
        )
    elif parser.has_section("wireguard"):
        innercity = _load_tunnel(
            parser,
            "wireguard",
            default_interface="wg0",
            default_config_path="/etc/wireguard/wg0.conf",
            default_cidr="10.66.0.0/24",
            default_reserved="10.66.0.1",
            cidr_key="allowed_cidr",
        )
    else:
        raise ValueError(
            "config needs [wireguard.innercity] (or legacy [wireguard])"
        )

    wan = _load_tunnel(
        parser,
        "wireguard.wan",
        default_interface="wg-wan",
        default_config_path="/etc/wireguard/wg-wan.conf",
        default_cidr="10.99.0.0/24",
        default_reserved="10.99.0.1",
        cidr_key="address_pool",
    )

    peer_timeout_seconds = parser.getint(
        "watchdog", "peer_timeout_seconds", fallback=600
    )
    check_interval_seconds = parser.getint(
        "watchdog", "check_interval_seconds", fallback=30
    )
    state_path = Path(
        parser.get(
            "watchdog",
            "state_path",
            fallback="/var/lib/freifunk-jena-wireguard-onboarder/state.json",
        )
    )

    return Config(
        listen=listen,
        port=port,
        rate_limit_seconds=rate_limit_seconds,
        innercity=innercity,
        wan=wan,
        peer_timeout_seconds=peer_timeout_seconds,
        check_interval_seconds=check_interval_seconds,
        state_path=state_path,
    )
