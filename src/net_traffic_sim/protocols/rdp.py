"""RDP (Remote Desktop Protocol) traffic generators."""

from __future__ import annotations

import random
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    ADMIN_WORKSTATION_IPS,
    DOMAIN_CONTROLLER_IP,
    EXTERNAL_HOST_IPS,
    RDP_CLIENT_SIZES,
    RDP_SERVER_SIZES,
    RETRANSMISSION_RATE_OTHER,
    SHAREPOINT_SERVER_IP,
    SQL_SERVER_IP,
    TCP_WINDOW_RDP_CLIENT,
    TCP_WINDOW_RDP_SERVER,
)
from ..logging_setup import get_logger
from ..state import generator
from ..tcp import (
    apply_retransmissions_smart,
    create_tcp_ack,
    create_tcp_psh_ack,
    exponential_delay,
    tcp_handshake,
)

logger = get_logger(__name__)


def generate_rdp_application_data(size):
    """Generate TLSv1.2 Application Data for RDP"""
    app_data = b"\x17\x03\x03"  # Application Data, TLS 1.2
    content = b"\x00" * (size - 5)
    app_data += struct.pack(">H", len(content))
    app_data += content
    return app_data


def generate_rdp_session(src_ip, dst_ip, sport, start_time, duration):
    """Generate RDP session over TLS 1.2"""
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 3389, current_time))
    current_time += random.uniform(0.010, 0.050)

    conn = generator.get_connection(src_ip, dst_ip, sport, 3389)
    conn_server = generator.get_connection(dst_ip, src_ip, 3389, sport)

    # Simplified TLS handshake (not shown in detail)
    current_time += random.uniform(0.1, 0.3)

    # RDP session - continuous Application Data exchange
    rdp_window_server = TCP_WINDOW_RDP_SERVER[0]
    rdp_window_index = 0

    exchange_count = 0
    max_exchanges = int(duration * 1)  # ~8 exchanges per second

    while current_time < start_time + duration and exchange_count < max_exchanges:
        # Client sends command/input
        client_size = random.choice(RDP_CLIENT_SIZES)
        client_data = generate_rdp_application_data(client_size)

        pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 3389, conn.seq, conn.ack, TCP_WINDOW_RDP_CLIENT, client_data, current_time)
        packets.append(pkt)
        conn.seq += len(client_data)
        current_time += exponential_delay(0.003, 0.008, 200)

        # Server ACK
        pkt = create_tcp_ack(dst_ip, src_ip, 3389, sport, conn_server.seq, conn.seq, rdp_window_server, current_time)
        packets.append(pkt)
        current_time += exponential_delay(0.002, 0.005, 300)

        # Server sends screen update
        server_size = random.choice(RDP_SERVER_SIZES)
        server_data = generate_rdp_application_data(server_size)

        pkt = create_tcp_psh_ack(dst_ip, src_ip, 3389, sport, conn_server.seq, conn.seq, rdp_window_server, server_data, current_time)
        packets.append(pkt)
        conn_server.seq += len(server_data)
        conn.ack = conn_server.seq
        current_time += exponential_delay(0.003, 0.007, 250)

        # Client ACK
        pkt = create_tcp_ack(src_ip, dst_ip, sport, 3389, conn.seq, conn.ack, TCP_WINDOW_RDP_CLIENT, current_time)
        packets.append(pkt)

        # Window growth (simulate receive buffer emptying)
        if exchange_count % 50 == 0 and rdp_window_index < len(TCP_WINDOW_RDP_SERVER) - 1:
            rdp_window_index += 1
            rdp_window_server = TCP_WINDOW_RDP_SERVER[rdp_window_index]

        # Variable pause (user interaction)
        if random.random() < 0.1:  # 10% chance of idle
            current_time += random.uniform(0.5, 2.0)
        else:
            current_time += exponential_delay(0.010, 0.060, 30)

        exchange_count += 1

    return packets


def generate_rdp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate RDP traffic from external IPs to servers."""
    logger.info("[+] Generating RDP traffic (TLSv1.2 on port 3389)...")
    all_packets = []

    # Create 2-3 RDP sessions
    sessions = [
        (EXTERNAL_HOST_IPS[0], SHAREPOINT_SERVER_IP, "External admin 1"),
        (EXTERNAL_HOST_IPS[1], SQL_SERVER_IP, "External admin 2"),
        (ADMIN_WORKSTATION_IPS[0], DOMAIN_CONTROLLER_IP, "Internal admin"),
    ]

    for src_ip, dst_ip, desc in sessions[: random.randint(2, 3)]:
        sport = generator.allocate_port(src_ip)
        logger.info(f"    RDP session: {desc} ({src_ip} -> {dst_ip})")

        session_packets = generate_rdp_session(src_ip, dst_ip, sport, start_time + random.uniform(0, 60), duration)
        all_packets.extend(session_packets)

    # Apply light retransmissions
    all_packets = apply_retransmissions_smart(all_packets, RETRANSMISSION_RATE_OTHER)

    logger.info(f"    RDP traffic: {len(all_packets)} packets")
    if serializer is not None:
        logger.info(f"    Writing {len(all_packets)} RDP packets to PCAP...")
        for pkt in all_packets:
            serializer.add_packet(pkt, pkt.time)
        return []
    return all_packets


__all__ = ["generate_rdp_application_data", "generate_rdp_session", "generate_rdp_traffic"]
