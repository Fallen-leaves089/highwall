"""Source-address policy helpers.

Deny rules always win. An empty allow list means "allow any address that is
not denied"; set ``server.require_client_allowlist`` or populate the list for
an explicit default-deny posture.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .config import IPNetwork

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def normalize_ip(value: str) -> IPAddress | None:
    """Parse an address and unmap IPv4-mapped IPv6 addresses."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def ip_in_networks(address: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    """Return True when the address belongs to any network of the same family."""
    return any(address.version == network.version and address in network for network in networks)


@dataclass(frozen=True)
class SourcePolicy:
    allowed: tuple[IPNetwork, ...]
    denied: tuple[IPNetwork, ...]

    def evaluate(self, address: IPAddress) -> tuple[bool, str]:
        if ip_in_networks(address, self.denied):
            return False, "source_denied"
        if self.allowed and not ip_in_networks(address, self.allowed):
            return False, "source_not_allowed"
        return True, "allowed"


def policy_from_networks(
    allowed: tuple[IPNetwork, ...], denied: tuple[IPNetwork, ...]
) -> SourcePolicy:
    return SourcePolicy(allowed=allowed, denied=denied)

