"""Network protocol traffic generators (DHCP, DHCPv6, IPv6 ND, NTP)."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from scapy.layers.inet import UDP
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, IPv6
from scapy.layers.l2 import Ether

from ..config import (
    DHCP_LEASES_PER_HOUR,
    DOMAIN_CONTROLLER_IP,
    IPV6_ND_EVENTS_PER_HOUR,
    IPV6_PREFIX,
    NTP_QUERIES_PER_HOUR,
    NTP_SERVER_POOL,
    USER_WORKSTATION_IPS,
)
from ..state import get_mac_fast, random_pool
from .base import _emit_packet, _udp6_packet, _udp_packet


def generate_dhcp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate basic DHCP discover/offer/request/ack exchanges."""
    packets = []
    lease_events = max(1, int((duration / 3600) * DHCP_LEASES_PER_HOUR))
    current_time = start_time
    for _ in range(lease_events):
        client_ip = random.choice(USER_WORKSTATION_IPS)
        broadcast_ip = "255.255.255.255"
        discover = _udp_packet(
            client_ip,
            broadcast_ip,
            68,
            67,
            b"DHCPDISCOVER",
            current_time,
            dst_mac="ff:ff:ff:ff:ff:ff",
        )
        _emit_packet(serializer, packets, discover, current_time)
        current_time += random_pool.delay_small()

        offer = _udp_packet(
            DOMAIN_CONTROLLER_IP,
            broadcast_ip,
            67,
            68,
            b"DHCPOFFER",
            current_time,
            dst_mac="ff:ff:ff:ff:ff:ff",
        )
        _emit_packet(serializer, packets, offer, current_time)
        current_time += random_pool.delay_small()

        request = _udp_packet(
            client_ip,
            broadcast_ip,
            68,
            67,
            b"DHCPREQUEST",
            current_time,
            dst_mac="ff:ff:ff:ff:ff:ff",
        )
        _emit_packet(serializer, packets, request, current_time)
        current_time += random_pool.delay_small()

        ack = _udp_packet(
            DOMAIN_CONTROLLER_IP,
            broadcast_ip,
            67,
            68,
            b"DHCPACK",
            current_time,
            dst_mac="ff:ff:ff:ff:ff:ff",
        )
        _emit_packet(serializer, packets, ack, current_time)
        current_time += random.uniform(30, 180)

    return packets if serializer is None else []


def generate_dhcpv6_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate basic DHCPv6 solicit/advertise/request/reply exchanges."""
    packets = []
    lease_events = max(1, int((duration / 3600) * DHCP_LEASES_PER_HOUR))
    current_time = start_time
    for _ in range(lease_events):
        client_ip = f"{IPV6_PREFIX}50:{random.randint(10, 200):x}"
        server_ip = f"{IPV6_PREFIX}10:10"
        solicit = _udp6_packet(client_ip, "ff02::1:2", 546, 547, b"DHCPv6 SOLICIT", current_time)
        _emit_packet(serializer, packets, solicit, current_time)
        current_time += random_pool.delay_small()

        advertise = _udp6_packet(server_ip, client_ip, 547, 546, b"DHCPv6 ADVERTISE", current_time)
        _emit_packet(serializer, packets, advertise, current_time)
        current_time += random_pool.delay_small()

        request = _udp6_packet(client_ip, server_ip, 546, 547, b"DHCPv6 REQUEST", current_time)
        _emit_packet(serializer, packets, request, current_time)
        current_time += random_pool.delay_small()

        reply = _udp6_packet(server_ip, client_ip, 547, 546, b"DHCPv6 REPLY", current_time)
        _emit_packet(serializer, packets, reply, current_time)
        current_time += random.uniform(30, 180)

    return packets if serializer is None else []


def generate_ipv6_nd_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate IPv6 neighbor discovery traffic."""
    packets = []
    events = max(1, int((duration / 3600) * IPV6_ND_EVENTS_PER_HOUR))
    current_time = start_time
    for _ in range(events):
        src_ip = f"{IPV6_PREFIX}50:{random.randint(10, 200):x}"
        dst_ip = f"{IPV6_PREFIX}10:10"
        ns = Ether(src=get_mac_fast(USER_WORKSTATION_IPS[0]), dst="33:33:00:00:00:01")
        ns /= IPv6(src=src_ip, dst="ff02::1:ff00:1")
        ns /= ICMPv6ND_NS(tgt=dst_ip)
        ns.time = current_time
        _emit_packet(serializer, packets, ns, current_time)
        current_time += random_pool.delay_small()

        na = Ether(src=get_mac_fast(USER_WORKSTATION_IPS[0]), dst="33:33:00:00:00:01")
        na /= IPv6(src=dst_ip, dst=src_ip)
        na /= ICMPv6ND_NA(tgt=dst_ip)
        na.time = current_time
        _emit_packet(serializer, packets, na, current_time)
        current_time += random.uniform(120, 300)
    return packets if serializer is None else []


def generate_ntp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate NTP sync traffic."""
    packets = []
    queries = max(1, int((duration / 3600) * NTP_QUERIES_PER_HOUR))
    current_time = start_time
    for _ in range(queries):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        ntp_host = random.choice(NTP_SERVER_POOL)
        dst_ip = ntp_host[1]
        req = _udp_packet(src_ip, dst_ip, random_pool.port(), 123, b"\x1b" + b"\x00" * 47, current_time)
        _emit_packet(serializer, packets, req, current_time)
        current_time += random_pool.delay_small()
        resp = _udp_packet(dst_ip, src_ip, 123, req[UDP].sport, b"\x1c" + b"\x00" * 47, current_time)
        _emit_packet(serializer, packets, resp, current_time)
        current_time += random.uniform(300, 900)
    return packets if serializer is None else []


__all__ = [
    "generate_dhcp_traffic",
    "generate_dhcpv6_traffic",
    "generate_ipv6_nd_traffic",
    "generate_ntp_traffic",
]
