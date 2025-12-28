"""Mail protocol traffic generators (SMTP, IMAP, POP3)."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    IMAP_SESSIONS_PER_HOUR,
    MAIL_SERVER_IP,
    POP3_SESSIONS_PER_HOUR,
    SMTP_SESSIONS_PER_HOUR,
    USER_WORKSTATION_IPS,
)
from .base import _emit_packet, _simple_tcp_exchange


def generate_smtp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate SMTP session traffic."""
    packets = []
    sessions = max(1, int((duration / 3600) * SMTP_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        payload = "EHLO corp.local\r\nMAIL FROM:<user@corp.local>\r\nRCPT TO:<helpdesk@corp.local>\r\nDATA\r\n.\r\n"
        response = "250 OK\r\n"
        exchange = _simple_tcp_exchange(src_ip, MAIL_SERVER_IP, 25, current_time, payload, response)
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(300, 900)
    return packets if serializer is None else []


def generate_imap_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate IMAP session traffic."""
    packets = []
    sessions = max(1, int((duration / 3600) * IMAP_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        exchange = _simple_tcp_exchange(src_ip, MAIL_SERVER_IP, 143, current_time, "a1 LOGIN user ***\r\n", "a1 OK\r\n")
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(300, 900)
    return packets if serializer is None else []


def generate_pop3_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate POP3 session traffic."""
    packets = []
    sessions = max(1, int((duration / 3600) * POP3_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        exchange = _simple_tcp_exchange(src_ip, MAIL_SERVER_IP, 110, current_time, "USER user\r\nPASS ***\r\n", "+OK\r\n")
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(300, 900)
    return packets if serializer is None else []


__all__ = [
    "generate_smtp_traffic",
    "generate_imap_traffic",
    "generate_pop3_traffic",
]
