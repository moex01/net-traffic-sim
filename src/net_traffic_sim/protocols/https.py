"""HTTPS/TLS protocol traffic generators."""

from __future__ import annotations

import random
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    EXTERNAL_DOMAINS,
    RETRANSMISSION_RATE_OTHER,
    SHAREPOINT_SERVER_IP,
    TCP_WINDOW_HTTPS,
    USER_WORKSTATION_IPS,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import (
    apply_retransmissions_smart,
    create_tcp_ack,
    create_tcp_psh_ack,
    exponential_delay,
    tcp_handshake,
)

logger = get_logger(__name__)


def generate_tls_client_hello(sni, timestamp):
    """Generate TLS 1.3 Client Hello payload"""
    # Simplified TLS 1.3 Client Hello structure
    client_hello = b"\x16\x03\x01"  # Content Type: Handshake, Version: TLS 1.0 (compatibility)

    # Handshake header
    handshake = b"\x01"  # Handshake Type: Client Hello

    # Client Hello data
    hello_data = b"\x03\x03"  # TLS version 1.2 (in legacy field)
    hello_data += struct.pack(">I", int(timestamp))  # Random (timestamp)
    hello_data += b"\x00" * 28  # Random bytes
    hello_data += b"\x00"  # Session ID length

    # Cipher suites
    cipher_suites = b"\x00\x2c"  # Length of cipher suites
    cipher_suites += b"\x13\x01"  # TLS_AES_128_GCM_SHA256
    cipher_suites += b"\x13\x02"  # TLS_AES_256_GCM_SHA384
    cipher_suites += b"\x13\x03"  # TLS_CHACHA20_POLY1305_SHA256
    hello_data += cipher_suites

    # Compression methods
    hello_data += b"\x01\x00"  # Compression: none

    # Extensions (including SNI)
    extensions = b"\x00\x00"  # SNI extension
    extensions += struct.pack(">H", len(sni) + 5)  # SNI length
    extensions += struct.pack(">H", len(sni) + 3)  # Server name list length
    extensions += b"\x00"  # Name type: host_name
    extensions += struct.pack(">H", len(sni))  # Hostname length
    extensions += sni.encode()

    # Supported versions extension (TLS 1.3)
    extensions += b"\x00\x2b\x00\x03\x02\x03\x04"  # TLS 1.3

    hello_data += struct.pack(">H", len(extensions))
    hello_data += extensions

    # Complete handshake message
    handshake += struct.pack(">I", len(hello_data))[1:]  # 3-byte length
    handshake += hello_data

    # TLS record
    client_hello += struct.pack(">H", len(handshake))
    client_hello += handshake

    # Pad to realistic size (1816-1880 bytes from real traffic)
    target_size = random.choice([1816, 1880])
    client_hello += b"\x00" * (target_size - len(client_hello))

    return client_hello[:target_size]


def generate_tls_server_hello(timestamp):
    """Generate TLS 1.3 Server Hello + Application Data payload"""
    # Simplified TLS 1.3 Server Hello

    # Large server hello with certificates (4000-4500 bytes from real traffic)
    hello_data = b"\x02"  # Server Hello
    hello_data += b"\x00\x00\x76"  # Length
    hello_data += b"\x03\x03"  # TLS 1.2
    hello_data += struct.pack(">I", int(timestamp))
    hello_data += b"\x00" * 28  # Random
    hello_data += b"\x13\x01"  # Cipher: TLS_AES_128_GCM_SHA256
    hello_data += b"\x00"  # Compression: none

    # Change Cipher Spec
    ccs = b"\x14\x03\x03\x00\x01\x01"

    # Application Data (certificates, key exchange)
    app_data = b"\x17\x03\x03"  # Application Data
    app_data_content = b"\x00" * 4000  # Simulated encrypted certificates
    app_data += struct.pack(">H", len(app_data_content))
    app_data += app_data_content

    payload = hello_data + ccs + app_data

    # Pad to realistic size
    target_size = random.randint(4000, 4500)
    payload += b"\x00" * (target_size - len(payload))

    return payload[:target_size]


def generate_tls_application_data(size):
    """Generate TLS Application Data payload"""
    app_data = b"\x17\x03\x03"  # Application Data, TLS 1.2
    content = b"\x00" * (size - 5)
    app_data += struct.pack(">H", len(content))
    app_data += content
    return app_data


def generate_https_session(src_ip, dst_ip, sport, sni, start_time):
    """Generate TLS 1.3 HTTPS session"""
    packets = []
    current_time = start_time

    # TCP handshake with ECN
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 443, current_time))
    current_time += random.uniform(0.010, 0.050)

    conn = generator.get_connection(src_ip, dst_ip, sport, 443)
    conn_server = generator.get_connection(dst_ip, src_ip, 443, sport)

    # TLS Client Hello
    client_hello = generate_tls_client_hello(sni, current_time)
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 443, conn.seq, conn.ack, random.choice(TCP_WINDOW_HTTPS), client_hello, current_time)
    packets.append(pkt)
    conn.seq += len(client_hello)
    current_time += random.uniform(0.030, 0.100)

    # Server ACK
    pkt = create_tcp_ack(dst_ip, src_ip, 443, sport, conn_server.seq, conn.seq, 65535, current_time)
    packets.append(pkt)
    current_time += random_pool.delay_handshake()

    # TLS Server Hello + Certificates
    server_hello = generate_tls_server_hello(current_time)
    pkt = create_tcp_psh_ack(dst_ip, src_ip, 443, sport, conn_server.seq, conn.seq, 65535, server_hello, current_time)
    packets.append(pkt)
    conn_server.seq += len(server_hello)
    conn.ack = conn_server.seq
    current_time += random_pool.delay_handshake()

    # Client ACK
    pkt = create_tcp_ack(src_ip, dst_ip, sport, 443, conn.seq, conn.ack, random.choice(TCP_WINDOW_HTTPS), current_time)
    packets.append(pkt)
    current_time += random.uniform(0.002, 0.008)

    # Client Change Cipher Spec + Application Data
    ccs_size = 138
    ccs_data = generate_tls_application_data(ccs_size)
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 443, conn.seq, conn.ack, random.choice(TCP_WINDOW_HTTPS), ccs_data, current_time)
    packets.append(pkt)
    conn.seq += len(ccs_data)
    current_time += random_pool.delay_small()

    # Client HTTP request (encrypted)
    http_req_size = random.choice([150, 493])
    http_req = generate_tls_application_data(http_req_size)
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 443, conn.seq, conn.ack, random.choice(TCP_WINDOW_HTTPS), http_req, current_time)
    packets.append(pkt)
    conn.seq += len(http_req)
    current_time += random.uniform(0.050, 0.200)

    # Server response (multiple Application Data packets)
    for _ in range(random.randint(3, 8)):
        resp_size = random.randint(800, 1400)
        resp_data = generate_tls_application_data(resp_size)
        pkt = create_tcp_psh_ack(dst_ip, src_ip, 443, sport, conn_server.seq, conn.seq, 65535, resp_data, current_time)
        packets.append(pkt)
        conn_server.seq += len(resp_data)
        current_time += exponential_delay(0.002, 0.020, 100)

        # Client ACK
        pkt = create_tcp_ack(src_ip, dst_ip, sport, 443, conn.seq, conn_server.seq, random.choice(TCP_WINDOW_HTTPS), current_time)
        packets.append(pkt)
        conn.ack = conn_server.seq
        current_time += exponential_delay(0.001, 0.005, 200)

    return packets


def generate_https_external_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate HTTPS traffic to external domains"""
    logger.info("[+] Generating HTTPS external traffic (TLS 1.3)...")

    use_serializer = serializer is not None
    all_packets = []

    current_time = start_time
    session_count = 0
    target_sessions = int(duration * 0.5)  # ~0.5 sessions per second

    while current_time < start_time + duration and session_count < target_sessions:
        src_ip = random.choice(USER_WORKSTATION_IPS + [SHAREPOINT_SERVER_IP])
        sport = generator.allocate_port(src_ip)

        # Choose external domain and IP
        domain = random.choice(EXTERNAL_DOMAINS)
        dst_ip = f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

        session_packets = generate_https_session(src_ip, dst_ip, sport, domain, current_time)
        all_packets.extend(session_packets)

        session_count += 1
        current_time += random.uniform(2, 10)

    # Apply light retransmissions KEPT
    all_packets = apply_retransmissions_smart(all_packets, RETRANSMISSION_RATE_OTHER)

    logger.info(f"    HTTPS traffic: {len(all_packets)} packets ({session_count} sessions)")

    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(all_packets)} HTTPS packets to PCAP...")
        for pkt in all_packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return all_packets  # Return for backward compatibility


__all__ = [
    "generate_tls_client_hello",
    "generate_tls_server_hello",
    "generate_tls_application_data",
    "generate_https_session",
    "generate_https_external_traffic",
]
