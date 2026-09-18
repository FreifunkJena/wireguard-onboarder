"""Allocate the next free IPv4 /32 from a configured pool."""

from __future__ import annotations

import ipaddress


class PoolExhaustedError(RuntimeError):
    """No free addresses left in the pool."""


def allocate_next(
    pool: ipaddress.IPv4Network,
    used: set[str],
    reserved: frozenset[ipaddress.IPv4Address],
) -> str:
    """Return the next free host as ``a.b.c.d/32``.

    ``used`` contains AllowedIPs strings already assigned (e.g. ``10.99.0.5/32``).
    """
    used_hosts: set[ipaddress.IPv4Address] = set()
    for entry in used:
        try:
            net = ipaddress.IPv4Network(entry, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            used_hosts.add(net.network_address)
        else:
            used_hosts.update(net.hosts())

    candidates = list(pool.hosts()) if pool.num_addresses > 2 else [pool.network_address]
    for host in candidates:
        if host in reserved:
            continue
        if host in used_hosts:
            continue
        return f"{host}/32"
    raise PoolExhaustedError(f"no free addresses in {pool}")
