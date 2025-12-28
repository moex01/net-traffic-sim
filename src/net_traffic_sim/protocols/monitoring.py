"""Monitoring protocol traffic generators (syslog, SNMP)."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from scapy.layers.inet import UDP

from ..config import (
    DOMAIN_CONTROLLER_IP,
    FILE_SHARE_SERVER_IP,
    FTP_SERVER_IP,
    LINUX_SERVER_IP,
    MONITORING_SERVER_IP,
    SNMP_POLLS_PER_MINUTE,
    SQL_SERVER_IP,
    SYSLOG_MESSAGES_PER_HOUR,
    SYSLOG_SERVER_IP,
    WEB_APP_SERVER_IP,
)
from ..state import random_pool
from .base import _emit_packet, _udp_packet


def generate_syslog_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate syslog messages."""
    packets = []
    messages = max(1, int((duration / 3600) * SYSLOG_MESSAGES_PER_HOUR))
    current_time = start_time
    for _ in range(messages):
        src_ip = random.choice([LINUX_SERVER_IP, FTP_SERVER_IP, WEB_APP_SERVER_IP, SQL_SERVER_IP])
        payload = b"<134>Oct 30 12:00:00 host app: routine log entry"
        pkt = _udp_packet(src_ip, SYSLOG_SERVER_IP, random_pool.port(), 514, payload, current_time)
        _emit_packet(serializer, packets, pkt, current_time)
        current_time += random.uniform(10, 60)
    return packets if serializer is None else []


def generate_snmp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate SNMP poll traffic."""
    packets = []
    polls = max(1, int((duration / 60) * SNMP_POLLS_PER_MINUTE))
    current_time = start_time
    for _ in range(polls):
        target_ip = random.choice([WEB_APP_SERVER_IP, SQL_SERVER_IP, DOMAIN_CONTROLLER_IP, FILE_SHARE_SERVER_IP])
        req = _udp_packet(MONITORING_SERVER_IP, target_ip, random_pool.port(), 161, b"SNMP GET", current_time)
        _emit_packet(serializer, packets, req, current_time)
        current_time += random_pool.delay_small()
        resp = _udp_packet(target_ip, MONITORING_SERVER_IP, 161, req[UDP].sport, b"SNMP RESPONSE", current_time)
        _emit_packet(serializer, packets, resp, current_time)
        current_time += random.uniform(5, 15)
    return packets if serializer is None else []


__all__ = [
    "generate_syslog_traffic",
    "generate_snmp_traffic",
]
