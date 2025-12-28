"""Remote access protocol traffic generators (SSH, FTP)."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    ADMIN_WORKSTATION_IPS,
    FTP_SERVER_IP,
    FTP_SESSIONS_PER_HOUR,
    LINUX_SERVER_IP,
    SSH_SESSIONS_PER_HOUR,
)
from .base import _emit_packet, _simple_tcp_exchange


def generate_ssh_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate SSH/SFTP traffic."""
    packets = []
    sessions = max(1, int((duration / 3600) * SSH_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(ADMIN_WORKSTATION_IPS)
        exchange = _simple_tcp_exchange(src_ip, LINUX_SERVER_IP, 22, current_time, b"SSH-2.0-OpenSSH_8.9", b"SSH-2.0-OpenSSH_8.9")
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(300, 600)
    return packets if serializer is None else []


def generate_ftp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate FTP/FTPS traffic."""
    packets = []
    sessions = max(1, int((duration / 3600) * FTP_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(ADMIN_WORKSTATION_IPS)
        exchange = _simple_tcp_exchange(src_ip, FTP_SERVER_IP, 21, current_time, "USER admin\r\nPASS ****\r\n", "230 Login OK\r\n")
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(300, 600)
    return packets if serializer is None else []


__all__ = [
    "generate_ssh_traffic",
    "generate_ftp_traffic",
]
