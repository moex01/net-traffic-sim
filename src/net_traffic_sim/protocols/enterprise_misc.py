"""Miscellaneous enterprise protocol traffic generators (LDAPS, WinRM, MSRPC)."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from scapy.layers.inet import TCP

from ..config import (
    ADMIN_WORKSTATION_IPS,
    DOMAIN_CONTROLLER_IP,
    LDAPS_SESSIONS_PER_HOUR,
    MSRPC_SESSIONS_PER_HOUR,
    USER_WORKSTATION_IPS,
    WINRM_SESSIONS_PER_HOUR,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import (
    create_tcp_ack,
    create_tcp_psh_ack,
    tcp_handshake,
)

logger = get_logger(__name__)


def _emit_packet(serializer, packets, pkt, timestamp):
    """Emit a packet to serializer or append to list."""
    if serializer is not None:
        serializer.add_packet(pkt, timestamp)
    else:
        packets.append(pkt)


def _simple_tcp_exchange(src_ip, dst_ip, dport, start_time, payload, response_payload=None):
    """Generate a simple TCP exchange with handshake, payload, and optional response."""
    packets = []
    sport = random_pool.port()
    handshake = tcp_handshake(src_ip, dst_ip, sport, dport, start_time)
    packets.extend(handshake)

    syn = handshake[0]
    syn_ack = handshake[1]
    conn_client = generator.get_connection(src_ip, dst_ip, sport, dport)
    conn_server = generator.get_connection(dst_ip, src_ip, dport, sport)
    conn_server.seq = syn_ack[TCP].seq + 1
    conn_server.ack = syn[TCP].seq + 1
    conn_server.established = True

    current_time = handshake[-1].time + random_pool.delay_small()
    if payload:
        if isinstance(payload, str):
            payload = payload.encode("ascii", "ignore")
        pkt = create_tcp_psh_ack(
            src_ip,
            dst_ip,
            sport,
            dport,
            conn_client.seq,
            conn_client.ack,
            65535,
            payload,
            current_time,
        )
        packets.append(pkt)
        conn_client.seq += len(payload)
        current_time += random_pool.delay_small()
        ack = create_tcp_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn_client.seq, 65535, current_time)
        packets.append(ack)

    if response_payload:
        current_time += random_pool.delay_small()
        if isinstance(response_payload, str):
            response_payload = response_payload.encode("ascii", "ignore")
        resp = create_tcp_psh_ack(
            dst_ip,
            src_ip,
            dport,
            sport,
            conn_server.seq,
            conn_client.seq,
            65535,
            response_payload,
            current_time,
        )
        packets.append(resp)
        conn_server.seq += len(response_payload)
        current_time += random_pool.delay_small()
        ack2 = create_tcp_ack(src_ip, dst_ip, sport, dport, conn_client.seq, conn_server.seq, 65535, current_time)
        packets.append(ack2)

    return packets


def generate_ldaps_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate LDAPS session traffic."""
    logger.info("[+] Generating LDAPS traffic...")
    packets = []
    sessions = max(1, int((duration / 3600) * LDAPS_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(ADMIN_WORKSTATION_IPS + USER_WORKSTATION_IPS)
        exchange = _simple_tcp_exchange(src_ip, DOMAIN_CONTROLLER_IP, 636, current_time, b"LDAPS BIND", b"LDAPS OK")
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(30, 90)

    logger.info(f"    LDAPS traffic: {len(packets)} packets ({sessions} sessions)")
    return packets if serializer is None else []


def generate_winrm_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate WinRM/WMI traffic."""
    logger.info("[+] Generating WinRM traffic...")
    packets = []
    sessions = max(1, int((duration / 3600) * WINRM_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(ADMIN_WORKSTATION_IPS)
        payload = "POST /wsman HTTP/1.1\r\nHost: winrm\r\n\r\n"
        response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        exchange = _simple_tcp_exchange(src_ip, DOMAIN_CONTROLLER_IP, 5985, current_time, payload, response)
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(60, 180)

    logger.info(f"    WinRM traffic: {len(packets)} packets ({sessions} sessions)")
    return packets if serializer is None else []


def generate_msrpc_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate MSRPC/DCERPC traffic."""
    logger.info("[+] Generating MSRPC traffic...")
    packets = []
    sessions = max(1, int((duration / 3600) * MSRPC_SESSIONS_PER_HOUR))
    current_time = start_time
    for _ in range(sessions):
        src_ip = random.choice(ADMIN_WORKSTATION_IPS)
        exchange = _simple_tcp_exchange(src_ip, DOMAIN_CONTROLLER_IP, 135, current_time, b"MSRPC BIND", b"MSRPC ACK")
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(60, 180)

    logger.info(f"    MSRPC traffic: {len(packets)} packets ({sessions} sessions)")
    return packets if serializer is None else []


__all__ = [
    "generate_ldaps_traffic",
    "generate_winrm_traffic",
    "generate_msrpc_traffic",
]
