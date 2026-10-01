"""Portable destination egress input parsing and canonicalization.

This module intentionally stops before provider-specific DNS resolution or
kernel configuration. It gives providers one deterministic, narrow
host:port representation without widening policy semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Iterable

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True, order=True)
class Destination:
    """Canonical policy destination.

    Hostnames are lower-cased and preserved as names; IP literals are
    canonicalized with ipaddress. Protocol is deliberately absent because the
    portable policy does not currently encode it.
    """

    host: str
    port: int

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("destination host must be non-empty")
        if not 1 <= self.port <= 65535:
            raise ValueError("destination port must be between 1 and 65535")


def parse_destination(value: str) -> Destination:
    """Parse exactly one host:port entry without implicit widening."""
    if not isinstance(value, str) or not value:
        raise ValueError("destination must be a non-empty string")
    if value.strip() != value or any(ch.isspace() for ch in value):
        raise ValueError("destination must not contain whitespace")
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or end + 1 >= len(value) or value[end + 1] != ":":
            raise ValueError("IPv6 destinations must use [address]:port syntax")
        host_text = value[1:end]
        port_text = value[end + 2:]
    else:
        if value.count(":") != 1:
            raise ValueError("destination must be host:port; IPv6 literals require brackets")
        host_text, port_text = value.rsplit(":", 1)

    if not port_text.isdecimal():
        raise ValueError("destination port must be decimal")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("destination port must be between 1 and 65535")

    try:
        host = str(ipaddress.ip_address(host_text))
    except ValueError:
        host = host_text.rstrip(".").lower()
        if not _HOSTNAME_RE.fullmatch(host):
            raise ValueError("destination host must be a DNS hostname or IP address")
        if host.startswith(".") or host.endswith("."):
            raise ValueError("destination hostname is invalid")

    return Destination(host, port)


def canonicalize_destinations(values: Iterable[str]) -> tuple[Destination, ...]:
    """Parse, deduplicate, and sort destination entries deterministically."""
    return tuple(sorted({parse_destination(value) for value in values}))


def canonical_destination_strings(values: Iterable[str]) -> tuple[str, ...]:
    """Return canonical host:port strings suitable for provider input."""
    result = []
    for destination in canonicalize_destinations(values):
        host = destination.host
        if ":" in host:
            host = f"[{host}]"
        result.append(f"{host}:{destination.port}")
    return tuple(result)
