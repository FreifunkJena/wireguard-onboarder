"""Validate WireGuard public keys and LibreMesh node addresses."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re


_COMMENT_SAFE = re.compile(r"[^\w\s.\-:/@]+", re.UNICODE)


class ValidationError(ValueError):
    """Invalid registration input."""


def validate_public_key(raw: object) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationError("public_key is required")
    key = raw.strip()
    try:
        decoded = base64.b64decode(key, validate=True)
    except binascii.Error as exc:
        raise ValidationError("public_key is not valid base64") from exc
    if len(decoded) != 32:
        raise ValidationError("public_key must decode to 32 bytes")
    # Canonical WireGuard form is standard base64 without newlines.
    canonical = base64.b64encode(decoded).decode("ascii")
    return canonical


def normalize_allowed_ips(raw: object) -> str:
    """Normalize a node IP or CIDR to an AllowedIPs string (IPv4 /32 or network)."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationError("address is required")
    text = raw.strip()
    try:
        if "/" in text:
            network = ipaddress.IPv4Network(text, strict=False)
            return str(network)
        address = ipaddress.IPv4Address(text)
        return f"{address}/32"
    except ValueError as exc:
        raise ValidationError("address must be an IPv4 address or CIDR") from exc


def validate_address_in_policy(
    allowed_ips: str,
    allowed_cidr: ipaddress.IPv4Network,
    reserved: frozenset[ipaddress.IPv4Address],
) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.IPv4Network(allowed_ips, strict=False)
    except ValueError as exc:
        raise ValidationError("address must be an IPv4 address or CIDR") from exc

    if not network.subnet_of(allowed_cidr):
        raise ValidationError("address is outside allowed_cidr")

    for host in network.hosts() if network.num_addresses > 1 else [network.network_address]:
        if host in reserved:
            raise ValidationError("address is reserved")
    if network.num_addresses == 1 and network.network_address in reserved:
        raise ValidationError("address is reserved")

    return network


def sanitize_comment(raw: object | None) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValidationError("comment must be a string")
    cleaned = _COMMENT_SAFE.sub("", raw).strip()
    if not cleaned:
        return None
    return cleaned[:120]
