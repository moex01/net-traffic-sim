"""ICMP and ARP protocol traffic generators."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from ..config import (
    ADMIN_WORKSTATION_IPS,
    DOMAIN_CONTROLLER_IP,
    FILE_SHARE_SERVER_IP,
    GATEWAY_IP,
    GATEWAY_MAC_ADDRESS,
    SHAREPOINT_SERVER_IP,
    SQL_SERVER_IP,
    USER_WORKSTATION_IPS,
)
from ..logging_setup import get_logger
from ..state import generator, get_mac_fast, random_pool

logger = get_logger(__name__)


def generate_icmp_ping(src_ip, dst_ip, seq, identifier, timestamp):
    """Generate ICMP Echo Request"""
    # Note: Route external traffic through gateway at Layer 2
    if dst_ip in [SHAREPOINT_SERVER_IP, SQL_SERVER_IP, DOMAIN_CONTROLLER_IP, FILE_SHARE_SERVER_IP]:
        # Internal ping - direct MAC
        dst_mac = get_mac_fast(dst_ip)
    else:
        # External ping - send to gateway MAC
        dst_mac = get_mac_fast(GATEWAY_IP)

    pkt = Ether(src=get_mac_fast(src_ip), dst=dst_mac)  # Note: Use cache
    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id(), ttl=128)  # Note: Add IP ID
    pkt /= ICMP(type=8, code=0, id=identifier, seq=seq)
    pkt /= Raw(load=b"\x61\x62\x63\x64\x65\x66\x67\x68" * 4)  # 32 bytes
    pkt.time = timestamp + random.uniform(0.0, 0.00005)
    return pkt


def generate_icmp_reply(src_ip, dst_ip, seq, identifier, timestamp):
    """Generate ICMP Echo Reply"""
    pkt = Ether(src=get_mac_fast(src_ip), dst=get_mac_fast(dst_ip))  # Note: Use cache

    # REALISTIC: TTL based on OS (Windows servers = 128, Linux = 64)
    # Assume servers are Windows, gateway/external are Linux
    if src_ip in [SHAREPOINT_SERVER_IP, SQL_SERVER_IP, FILE_SHARE_SERVER_IP]:
        ttl = 128  # Windows Server
    elif src_ip == DOMAIN_CONTROLLER_IP:
        ttl = 64  # Linux DC (could be 128 if Windows)
    else:
        ttl = 64  # Default for external/gateway

    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id(), ttl=ttl)  # Note: Add IP ID
    pkt /= ICMP(type=0, code=0, id=identifier, seq=seq)
    pkt /= Raw(load=b"\x61\x62\x63\x64\x65\x66\x67\x68" * 4)  # 32 bytes payload
    pkt.time = timestamp + random.uniform(0.0, 0.00005)
    return pkt


def generate_arp_request(src_ip, dst_ip, src_mac, timestamp):
    """Generate ARP Who-has request"""
    pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
    pkt /= ARP(op=1, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=dst_ip)
    pkt.time = timestamp + random.uniform(0.0, 0.00005)
    return pkt


def generate_arp_reply(src_ip, dst_ip, src_mac, dst_mac, timestamp):
    """Generate ARP reply"""
    pkt = Ether(src=src_mac, dst=dst_mac)
    pkt /= ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    pkt.time = timestamp + random.uniform(0.0, 0.00005)
    return pkt


def generate_arp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate periodic ARP requests/responses for gateway and servers"""
    logger.info("[+] Generating ARP traffic...")

    use_serializer = serializer is not None
    packets = []
    current_time = start_time

    # ARP targets: Gateway + all servers
    arp_targets = {
        GATEWAY_IP: GATEWAY_MAC_ADDRESS,
        SHAREPOINT_SERVER_IP: generator.mac_table[SHAREPOINT_SERVER_IP],
        SQL_SERVER_IP: generator.mac_table[SQL_SERVER_IP],
        DOMAIN_CONTROLLER_IP: generator.mac_table[DOMAIN_CONTROLLER_IP],
        FILE_SHARE_SERVER_IP: generator.mac_table[FILE_SHARE_SERVER_IP],
    }

    while current_time < start_time + duration:
        # Random host sends ARP request
        src_ip = random.choice(USER_WORKSTATION_IPS + ADMIN_WORKSTATION_IPS + [SHAREPOINT_SERVER_IP, SQL_SERVER_IP])
        target_ip = random.choice(list(arp_targets.keys()))

        # ARP Request (Who has X.X.X.X? Tell Y.Y.Y.Y)
        arp_req = Ether(src=generator.mac_table[src_ip], dst="ff:ff:ff:ff:ff:ff")
        arp_req /= ARP(op=1, hwsrc=generator.mac_table[src_ip], psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=target_ip)
        arp_req.time = current_time
        packets.append(arp_req)

        # ARP Reply (X.X.X.X is at AA:BB:CC:DD:EE:FF)
        reply_time = current_time + random.uniform(0.001, 0.010)
        arp_reply = Ether(src=arp_targets[target_ip], dst=generator.mac_table[src_ip])
        arp_reply /= ARP(op=2, hwsrc=arp_targets[target_ip], psrc=target_ip, hwdst=generator.mac_table[src_ip], pdst=src_ip)
        arp_reply.time = reply_time
        packets.append(arp_reply)

        # ARP cache refresh every 5-15 minutes per host
        current_time += random.uniform(300, 900)

    logger.info(f"    ARP traffic: {len(packets)} packets")
    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(packets)} ARP packets to PCAP...")
        for pkt in packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return packets  # Return for backward compatibility


def generate_icmp_arp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate ICMP and ARP background traffic scaled to duration"""
    logger.info("[+] Generating ICMP and ARP traffic...")

    use_serializer = serializer is not None
    packets = []

    current_time = start_time

    # Scale ping frequency based on duration.
    # For 24 hours: ~40 ping sessions; for 1 hour: ~5 ping sessions.
    num_ping_sessions = max(5, int(duration / 2160))  # One session per ~36 minutes

    # Periodic user pings to check connectivity (INTERNAL)
    ping_pairs = [
        (USER_WORKSTATION_IPS[0], SHAREPOINT_SERVER_IP),
        (USER_WORKSTATION_IPS[3], DOMAIN_CONTROLLER_IP),
        (USER_WORKSTATION_IPS[7], FILE_SHARE_SERVER_IP),
        (ADMIN_WORKSTATION_IPS[0], SQL_SERVER_IP),
    ]

    for _session in range(num_ping_sessions):
        src, dst = random.choice(ping_pairs)
        ping_time = current_time + random.uniform(0, duration)
        identifier = random_pool.ip_id()

        for seq in range(1, 5):  # 4 pings (typical Windows behavior)
            req = generate_icmp_ping(src, dst, seq, identifier, ping_time)
            packets.append(req)

            reply_time = ping_time + random.uniform(0.0005, 0.003)  # 0.5-3ms latency
            reply = generate_icmp_reply(dst, src, seq, identifier, reply_time)
            packets.append(reply)

            ping_time += 1.0  # 1 second between pings

    #  External connectivity checks (documentation ranges).
    external_targets = ["192.0.2.1", "198.51.100.1", "203.0.113.1"]
    num_external_pings = max(3, int(duration / 7200))  # One per ~2 hours

    for _ in range(num_external_pings):
        src_ip = random.choice(USER_WORKSTATION_IPS + ADMIN_WORKSTATION_IPS)
        dst_ip = random.choice(external_targets)
        ping_time = start_time + random.uniform(0, duration)
        identifier = random_pool.ip_id()

        for seq in range(1, 5):
            req = Ether(src=get_mac_fast(src_ip), dst=get_mac_fast(GATEWAY_IP))
            req /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id(), ttl=128)
            req /= ICMP(type=8, code=0, id=identifier, seq=seq)
            req /= Raw(b"\x00" * 32)
            req.time = ping_time
            packets.append(req)

            # Reply with higher latency (external)
            reply_time = ping_time + random.uniform(0.015, 0.045)  # 15-45ms
            reply = Ether(src=get_mac_fast(GATEWAY_IP), dst=get_mac_fast(src_ip))
            reply /= IP(src=dst_ip, dst=src_ip, id=random_pool.ip_id(), ttl=56)
            reply /= ICMP(type=0, code=0, id=identifier, seq=seq)
            reply /= Raw(b"\x00" * 32)
            reply.time = reply_time
            packets.append(reply)

            ping_time += 1.0

    # ARP requests/replies at start of connections
    arp_time = start_time + random.uniform(0, 10)

    for user_ip in USER_WORKSTATION_IPS[:10]:  # First 10 users
        # User ARPs for gateway/servers
        # Include the gateway to simulate L2 reachability checks.
        targets = [SHAREPOINT_SERVER_IP, DOMAIN_CONTROLLER_IP, FILE_SHARE_SERVER_IP, GATEWAY_IP]
        target = random.choice(targets)

        arp_req = generate_arp_request(user_ip, target, generator.mac_table[user_ip], arp_time)
        packets.append(arp_req)

        arp_reply_pkt = generate_arp_reply(target, user_ip, generator.mac_table[target], generator.mac_table[user_ip], arp_time + random_pool.delay_minimal())
        packets.append(arp_reply_pkt)

        arp_time += random.uniform(0.1, 2.0)

    # Gratuitous ARP from servers (announcing presence)
    garp_time = start_time + random.uniform(60, 300)
    for server_ip in [SHAREPOINT_SERVER_IP, SQL_SERVER_IP, DOMAIN_CONTROLLER_IP, FILE_SHARE_SERVER_IP]:
        garp = Ether(src=generator.mac_table[server_ip], dst="ff:ff:ff:ff:ff:ff")
        garp /= ARP(op=2, hwsrc=generator.mac_table[server_ip], psrc=server_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=server_ip)
        garp.time = garp_time
        packets.append(garp)
        garp_time += random.uniform(1, 10)

    logger.info(f"    ICMP/ARP traffic: {len(packets)} packets")

    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(packets)} ICMP/ARP packets to PCAP...")
        for pkt in packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return packets  # Return for backward compatibility


__all__ = [
    "generate_icmp_ping",
    "generate_icmp_reply",
    "generate_arp_request",
    "generate_arp_reply",
    "generate_arp_traffic",
    "generate_icmp_arp_traffic",
]
