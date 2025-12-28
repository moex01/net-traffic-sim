"""VoIP protocol traffic generators (SIP, RTP)."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    SIP_CALLS_PER_HOUR,
    USER_WORKSTATION_IPS,
    VOIP_PBX_IP,
    VOIP_PHONE_IPS,
)
from ..state import random_pool
from .base import _emit_packet, _udp_packet


def generate_sip_rtp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate basic SIP signaling with RTP media packets."""
    packets = []
    calls = max(1, int((duration / 3600) * SIP_CALLS_PER_HOUR))
    current_time = start_time
    for _ in range(calls):
        phone_ip = random.choice(VOIP_PHONE_IPS) if VOIP_PHONE_IPS else random.choice(USER_WORKSTATION_IPS)
        invite = _udp_packet(phone_ip, VOIP_PBX_IP, 5060, 5060, b"SIP INVITE", current_time)
        _emit_packet(serializer, packets, invite, current_time)
        current_time += random_pool.delay_small()
        ok = _udp_packet(VOIP_PBX_IP, phone_ip, 5060, 5060, b"SIP 200 OK", current_time)
        _emit_packet(serializer, packets, ok, current_time)
        current_time += random_pool.delay_small()

        rtp_port = random.randint(10000, 20000)
        for _ in range(5):
            rtp = _udp_packet(phone_ip, VOIP_PBX_IP, rtp_port, rtp_port, b"RTP", current_time)
            _emit_packet(serializer, packets, rtp, current_time)
            current_time += 0.02
        current_time += random.uniform(60, 180)
    return packets if serializer is None else []


__all__ = [
    "generate_sip_rtp_traffic",
]
