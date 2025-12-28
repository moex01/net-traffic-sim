"""QUIC/HTTP3 protocol traffic generators."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    EXTERNAL_HOST_IPS,
    QUIC_SESSIONS_PER_HOUR,
    USER_WORKSTATION_IPS,
)
from ..state import random_pool
from .base import _emit_packet, _udp_packet


def generate_quic_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate QUIC/HTTP3 traffic."""
    packets = []
    sessions = max(1, int((duration / 3600) * QUIC_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        dst_ip = random.choice(EXTERNAL_HOST_IPS)
        pkt = _udp_packet(src_ip, dst_ip, random_pool.port(), 443, b"QUIC CLIENT HELLO", current_time)
        _emit_packet(serializer, packets, pkt, current_time)
        current_time += random.uniform(20, 120)
    return packets if serializer is None else []


__all__ = [
    "generate_quic_traffic",
]
