"""Name resolution discovery protocols (mDNS, LLMNR, NBNS)."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    LLMNR_QUERIES_PER_HOUR,
    NBNS_QUERIES_PER_HOUR,
    USER_WORKSTATION_IPS,
)
from ..state import random_pool
from .base import _emit_packet, _udp_packet


def generate_mdns_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate multicast DNS queries."""
    packets = []
    queries = max(1, int(duration / 600))
    current_time = start_time
    for _ in range(queries):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        pkt = _udp_packet(src_ip, "224.0.0.251", random_pool.port(), 5353, b"mDNS QUERY", current_time, dst_mac="ff:ff:ff:ff:ff:ff")
        _emit_packet(serializer, packets, pkt, current_time)
        current_time += random.uniform(30, 120)
    return packets if serializer is None else []


def generate_llmnr_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate LLMNR queries."""
    packets = []
    queries = max(1, int((duration / 3600) * LLMNR_QUERIES_PER_HOUR))
    current_time = start_time
    for _ in range(queries):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        pkt = _udp_packet(src_ip, "224.0.0.252", random_pool.port(), 5355, b"LLMNR QUERY", current_time, dst_mac="ff:ff:ff:ff:ff:ff")
        _emit_packet(serializer, packets, pkt, current_time)
        current_time += random.uniform(120, 300)
    return packets if serializer is None else []


def generate_nbns_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate NBNS broadcast queries."""
    packets = []
    queries = max(1, int((duration / 3600) * NBNS_QUERIES_PER_HOUR))
    current_time = start_time
    for _ in range(queries):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        pkt = _udp_packet(src_ip, "255.255.255.255", random_pool.port(), 137, b"NBNS QUERY", current_time, dst_mac="ff:ff:ff:ff:ff:ff")
        _emit_packet(serializer, packets, pkt, current_time)
        current_time += random.uniform(120, 300)
    return packets if serializer is None else []


def generate_ssdp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate SSDP discovery traffic."""
    packets = []
    queries = max(1, int(duration / 900))
    current_time = start_time
    for _ in range(queries):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        pkt = _udp_packet(src_ip, "239.255.255.250", random_pool.port(), 1900, b"M-SEARCH * HTTP/1.1", current_time, dst_mac="ff:ff:ff:ff:ff:ff")
        _emit_packet(serializer, packets, pkt, current_time)
        current_time += random.uniform(60, 180)
    return packets if serializer is None else []


__all__ = [
    "generate_mdns_traffic",
    "generate_llmnr_traffic",
    "generate_nbns_traffic",
    "generate_ssdp_traffic",
]
