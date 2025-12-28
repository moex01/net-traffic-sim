"""DNS protocol traffic generators."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from ..config import (
    DNS_TCP_QUERIES_PER_HOUR,
    DOMAIN_CONTROLLER_IP,
    EXTERNAL_DNS_IPS,
    EXTERNAL_DOMAINS,
    SHAREPOINT_SERVER_IP,
    SQL_SERVER_IP,
    USER_WORKSTATION_IPS,
    Config,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import exponential_delay
from .base import _emit_packet, _simple_tcp_exchange

logger = get_logger(__name__)


def generate_dns_query(src_ip, dst_ip, domain, qtype="A", timestamp=None):
    """Generate DNS query packet"""
    if timestamp is None:
        timestamp = generator.current_time

    sport = generator.allocate_port(src_ip)
    txid = random_pool.dns_txid()

    pkt = Ether(src=generator.mac_table.get(src_ip, "00:00:00:00:00:01"), dst=generator.mac_table.get(dst_ip, "00:00:00:00:00:02"))
    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id(src_ip, dst_ip))
    pkt /= UDP(sport=sport, dport=53)
    pkt /= DNS(id=txid, qr=0, opcode=0, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    pkt.time = timestamp + random.uniform(0.0, 0.00005)

    return pkt, txid, sport


def generate_dns_response(src_ip, dst_ip, sport, domain, txid, qtype="A", timestamp=None):
    """Generate DNS response packet"""
    if timestamp is None:
        timestamp = generator.current_time

    # Determine response
    if random.random() < 0.02:  # 2% NXDOMAIN
        rcode = 3  # NXDOMAIN
        an = None
    else:
        rcode = 0  # NOERROR
        if qtype == "A":
            # Generate realistic IP response
            if domain.endswith(".corp.local"):
                # Internal domain
                ip = f"10.3.{random.randint(10, 50)}.{random.randint(1, 254)}"
            else:
                # External domain - documentation range
                ip = random.choice(EXTERNAL_DNS_IPS)
            an = DNSRR(rrname=domain, type="A", rdata=ip, ttl=300)
        elif qtype == "AAAA":
            # IPv6 response or NXDOMAIN
            if random.random() < 0.5:
                rcode = 3
                an = None
            else:
                ipv6 = f"2001:db8::{random_pool.ip_id():x}"
                an = DNSRR(rrname=domain, type="AAAA", rdata=ipv6, ttl=300)
        else:
            an = None

    pkt = Ether(src=generator.mac_table.get(src_ip, "00:00:00:00:00:02"), dst=generator.mac_table.get(dst_ip, "00:00:00:00:00:01"))
    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id())
    pkt /= UDP(sport=53, dport=sport)
    pkt /= DNS(id=txid, qr=1, opcode=0, aa=0, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=domain, qtype=qtype), an=an if an else None)
    pkt.time = timestamp + random.uniform(0.0, 0.00005)

    return pkt


def generate_dns_response_with_ttl(src_ip, dst_ip, sport, domain, txid, qtype="A", timestamp=None, response_ip=None):
    """Generate DNS response packet WITH realistic TTL"""
    if timestamp is None:
        timestamp = generator.current_time

    # Determine realistic TTL based on domain type
    if domain.endswith(".corp.local"):
        ttl = random.randint(900, 3600)  # Internal: 15min-1hr
    elif any(cdn in domain for cdn in ["cloudfront", "akamai", "fastly", "cdn", "cdninstagram", "fbcdn", "twimg"]):
        ttl = random.randint(60, 300)  # CDN: 1-5 minutes
    elif domain.endswith(".com") or domain.endswith(".net") or domain.endswith(".co.uk"):
        ttl = random.randint(300, 86400)  # Public: 5min-24hr
    else:
        ttl = random.randint(3600, 86400)  # Long-lived: 1-24hr

    # Determine response
    if random.random() < 0.02:  # 2% NXDOMAIN
        rcode = 3  # NXDOMAIN
        an = None
    else:
        rcode = 0  # NOERROR
        if qtype == "A":
            # Generate realistic IP response
            if domain.endswith(".corp.local"):
                ip = response_ip or f"10.3.{random.randint(10, 50)}.{random.randint(1, 254)}"
            else:
                ip = response_ip or random.choice(EXTERNAL_DNS_IPS)
            an = DNSRR(rrname=domain, type="A", rdata=ip, ttl=ttl)  # <- Use dynamic TTL
        elif qtype == "AAAA":
            if random.random() < 0.5:
                rcode = 3
                an = None
            else:
                ipv6 = response_ip or (f"2001:db8::{random_pool.ip_id():x}")
                an = DNSRR(rrname=domain, type="AAAA", rdata=ipv6, ttl=ttl)  # <- Use dynamic TTL
        else:
            an = None

    pkt = Ether(src=generator.mac_table.get(src_ip, "00:00:00:00:00:02"), dst=generator.mac_table.get(dst_ip, "00:00:00:00:00:01"))
    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id())
    pkt /= UDP(sport=53, dport=sport)
    pkt /= DNS(id=txid, qr=1, opcode=0, aa=0, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=domain, qtype=qtype), an=an if an else None)
    pkt.time = timestamp + random.uniform(0.0, 0.00005)

    return pkt, ttl, an.rdata if an else None  # Return packet, TTL, and response


def generate_dns_traffic(
    start_time,
    duration,
    serializer: FastPacketSerializer | None = None,
    config: Config | None = None,
):
    """Generate DNS query/response traffic"""
    logger.info("[+] Generating DNS traffic...")
    config = config or Config.from_defaults()

    # If no serializer provided, use old method (backward compatible)
    if serializer is None:
        packets = []
        use_serializer = False
    else:
        packets = []  # Still keep for return compatibility
        use_serializer = True

    current_time = start_time
    query_count = 0
    target_queries = int(duration * config.dns_queries_per_sec)

    # Internal domains
    internal_domains = [f"{host}.corp.local" for host in ["sp-srv01", "sql-srv01", "dc01", "shr-srv01"]] + ["sharepoint.corp.local", "intranet.corp.local"]

    while current_time < start_time + duration and query_count < target_queries:
        # Choose source (user workstation or server)
        src_ip = random.choice(USER_WORKSTATION_IPS + [SHAREPOINT_SERVER_IP, SQL_SERVER_IP])

        # Choose domain type
        if random.random() < 0.3:  # 30% internal
            domain = random.choice(internal_domains)
            dns_server = DOMAIN_CONTROLLER_IP
        else:  # 70% external
            domain = random.choice(EXTERNAL_DOMAINS)
            dns_server = random.choice(["192.0.2.53", "198.51.100.53"])

        # Query type
        qtype = random.choices(["A", "AAAA", "PTR"], weights=[80, 15, 5])[0]

        cache_key = (domain, qtype)
        cached_response = None
        if cache_key in generator.dns_cache:
            cached_entry = generator.dns_cache[cache_key]
            if isinstance(cached_entry, tuple) and len(cached_entry) == 3:
                cache_time, cached_ttl, cached_response = cached_entry
            else:
                cache_time, cached_ttl = cached_entry  # Backward compatibility
            time_since_cached = current_time - cache_time

            # Calculate 90% of TTL threshold for early refresh consideration
            ttl_threshold = cached_ttl * 0.90

            if time_since_cached < ttl_threshold:
                # Within 90% of TTL - honor cache 95% of the time
                if random.random() < 0.95:  # 95% honor cache
                    current_time += exponential_delay(0.002, 0.5, 5)
                    continue
                # 5% still query despite cache (early refresh)
            elif time_since_cached < cached_ttl:
                # Between 90-100% of TTL - honor cache only 70% of the time
                if random.random() < 0.70:  # 70% honor cache in this zone
                    current_time += exponential_delay(0.002, 0.5, 5)
                    continue
                # 30% refresh early as TTL expiry approaches
            # If >= TTL, proceed with query (cache expired)

        query_pkt, txid, sport = generate_dns_query(src_ip, dns_server, domain, qtype, current_time)

        # WRITE OR STORE (depends on serializer)
        if use_serializer:
            serializer.add_packet(query_pkt, current_time)  # type: ignore
        else:
            packets.append(query_pkt)

        # Determine if this is internal or external DNS query
        is_internal_domain = domain.endswith(".corp.local") or dns_server == DOMAIN_CONTROLLER_IP

        # Set realistic latency based on domain type
        if is_internal_domain:
            # Internal DNS (Active Directory): 1-5ms
            latency = random.uniform(0.001, 0.005)
        else:
            # External DNS (Internet): 20-50ms
            latency = random.uniform(0.020, 0.050)

        response_time = current_time + latency
        response_pkt, ttl, response_ip = generate_dns_response_with_ttl(
            dns_server,
            src_ip,
            sport,
            domain,
            txid,
            qtype,
            response_time,
            response_ip=cached_response,
        )

        # WRITE OR STORE (depends on serializer)
        if use_serializer:
            serializer.add_packet(response_pkt, response_time)  # type: ignore
        else:
            packets.append(response_pkt)

        generator.dns_cache[cache_key] = (current_time, ttl, response_ip)
        current_time += exponential_delay(0.002, 0.5, 5)
        query_count += 1

    logger.info(f"    DNS traffic: {serializer.packet_count if use_serializer else len(packets)} packets ({query_count} queries)")  # type: ignore
    return packets


def generate_dns_query_response(src_ip, dns_server, domain, resolved_ip, timestamp):
    """Generate DNS query and response pair"""
    packets = []

    # DNS query
    query_pkt, txid, sport = generate_dns_query(src_ip, dns_server, domain, "A", timestamp)
    packets.append(query_pkt)

    # DNS response (20-80ms later)
    response_time = timestamp + random.uniform(0.020, 0.080)

    # Manually create response with resolved_ip
    pkt = Ether(src=generator.mac_table.get(dns_server, "00:00:00:00:00:02"), dst=generator.mac_table.get(src_ip, "00:00:00:00:00:01"))
    pkt /= IP(src=dns_server, dst=src_ip, id=random_pool.ip_id())
    pkt /= UDP(sport=53, dport=sport)
    pkt /= DNS(
        id=txid, qr=1, opcode=0, aa=0, rd=1, ra=1, rcode=0, qd=DNSQR(qname=domain, qtype="A"), an=DNSRR(rrname=domain, type="A", rdata=resolved_ip, ttl=300)
    )
    pkt.time = response_time
    packets.append(pkt)

    return packets


def generate_dns_tcp_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate DNS over TCP traffic."""
    packets = []
    queries = max(1, int((duration / 3600) * DNS_TCP_QUERIES_PER_HOUR))
    current_time = start_time
    for _ in range(queries):
        src_ip = random.choice(USER_WORKSTATION_IPS)
        exchange = _simple_tcp_exchange(src_ip, DOMAIN_CONTROLLER_IP, 53, current_time, b"DNS TCP QUERY", b"DNS TCP RESPONSE")
        for pkt in exchange:
            _emit_packet(serializer, packets, pkt, pkt.time)
        current_time = exchange[-1].time + random.uniform(120, 300)
    return packets if serializer is None else []


__all__ = [
    "generate_dns_query",
    "generate_dns_response",
    "generate_dns_response_with_ttl",
    "generate_dns_traffic",
    "generate_dns_query_response",
    "generate_dns_tcp_traffic",
]
