"""Kerberos and LDAP authentication protocol traffic generators."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..config import (
    DOMAIN_CONTROLLER_IP,
    SHAREPOINT_SERVER_IP,
    SQL_SERVER_IP,
    USER_WORKSTATION_IPS,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import (
    create_tcp_psh_ack,
    exponential_delay,
    tcp_handshake,
)

logger = get_logger(__name__)


# Realistic users database used by Kerberos and LDAP
REALISTIC_USERS = [
    ("jsmith", "James Smith", "james.smith@corp.local"),
    ("agarcia", "Angela Garcia", "angela.garcia@corp.local"),
    ("mzhou", "Ming Zhou", "ming.zhou@corp.local"),
    ("bwilson", "Brian Wilson", "brian.wilson@corp.local"),
    ("kjones", "Kevin Jones", "kevin.jones@corp.local"),
    ("ltaylor", "Lisa Taylor", "lisa.taylor@corp.local"),
    ("rhernandez", "Roberto Hernandez", "roberto.hernandez@corp.local"),
    ("clee", "Catherine Lee", "catherine.lee@corp.local"),
    ("dmiller", "David Miller", "david.miller@corp.local"),
    ("sarahc", "Sarah Chen", "sarah.chen@corp.local"),
    ("jdavis", "John Davis", "john.davis@corp.local"),
    ("mcampbell", "Michelle Campbell", "michelle.campbell@corp.local"),
    ("kpatel", "Kundan Patel", "kundan.patel@corp.local"),
    ("jrodriguez", "Javier Rodriguez", "javier.rodriguez@corp.local"),
    ("ekim", "Emily Kim", "emily.kim@corp.local"),
    ("trossiter", "Thomas Rossiter", "thomas.rossiter@corp.local"),
    ("jbrown", "Jessica Brown", "jessica.brown@corp.local"),
    ("mwright", "Michael Wright", "michael.wright@corp.local"),
    ("nwhite", "Nicole White", "nicole.white@corp.local"),
    ("gmorgan", "Gregory Morgan", "gregory.morgan@corp.local"),
]

# Simple username list for LDAP binds
REALISTIC_USERNAMES = [user[0] for user in REALISTIC_USERS]


def generate_kerberos_as_req(client_ip, timestamp):
    """Generate Kerberos AS-REQ (Authentication Service Request)"""
    # Simplified Kerberos AS-REQ
    as_req = b"\x6a"  # Application tag
    as_req += b"\x81\xa0"  # Length (simplified)
    as_req += b"\x30\x81\x9d"  # SEQUENCE

    # KDC-REQ-BODY
    as_req += b"\xa0\x03\x02\x01\x05"  # pvno: 5
    as_req += b"\xa1\x03\x02\x01\x0a"  # msg-type: AS-REQ (10)
    as_req += b"\xa2\x03\x02\x01\x00"  # PA-DATA (pre-auth)

    # Client name (simplified)
    # FIX: Extract only the username (first element of tuple)
    username_str = random.choice(REALISTIC_USERS)[0]  # <- Get just the username!
    # FIX: Convert to bytes
    username_bytes = username_str.encode("utf-8")

    as_req += b"\xa4" + bytes([len(username_bytes) + 2]) + b"\x30" + bytes([len(username_bytes)]) + username_bytes

    # Realm
    as_req += b"\xa5\x0b\x1b\x09CORP.LOCAL"

    # Server name (krbtgt)
    as_req += b"\xa6\x10\x30\x0e\xa0\x03\x02\x01\x02\xa1\x07\x30\x05\x1b\x03krbtgt"

    # Pad to realistic size
    as_req += b"\x00" * (200 - len(as_req))

    return as_req


def generate_kerberos_as_rep(timestamp):
    """Generate Kerberos AS-REP (Authentication Service Response)"""
    # Simplified Kerberos AS-REP with TGT
    as_rep = b"\x6b"  # Application tag
    as_rep += b"\x82\x01\x50"  # Length
    as_rep += b"\x30\x82\x01\x4c"  # SEQUENCE

    # pvno, msg-type
    as_rep += b"\xa0\x03\x02\x01\x05"  # pvno: 5
    as_rep += b"\xa1\x03\x02\x01\x0b"  # msg-type: AS-REP (11)

    # Encrypted ticket (TGT)
    as_rep += b"\xa3\x82\x01\x00"  # ticket
    as_rep += b"\x61\x81\xfd"  # Ticket APPLICATION 1
    as_rep += b"\x00" * 300  # Encrypted data (simplified)

    return as_rep


def generate_ldap_bind_request(username):
    """Generate LDAP Bind Request"""
    # Use short usernames (for example, jsmith, agarcia) in the bind DN.
    # Simplified LDAP Bind
    ldap = b"\x30"  # SEQUENCE
    ldap += b"\x39"  # Length

    # Message ID
    ldap += b"\x02\x01\x01"  # messageID: 1

    # Bind Request
    ldap += b"\x60\x34"  # bindRequest APPLICATION 0
    ldap += b"\x02\x01\x03"  # version: 3

    # DN - Format as CORP\username (Windows style)
    dn = f"CORP\\{username}".encode()
    ldap += b"\x04" + bytes([len(dn)]) + dn

    # Simple authentication
    ldap += b"\x80\x08password"  # Simple bind (password hidden)

    return ldap


def generate_ldap_search_request(base_dn, filter_str):
    """Generate LDAP Search Request"""
    ldap = b"\x30\x58"  # SEQUENCE
    ldap += b"\x02\x01\x02"  # messageID: 2

    # Search Request
    ldap += b"\x63\x53"  # searchRequest APPLICATION 3

    # Base DN
    base = base_dn.encode()
    ldap += b"\x04" + bytes([len(base)]) + base

    # Scope: wholeSubtree (2)
    ldap += b"\x0a\x01\x02"

    # DerefAliases: neverDerefAliases (0)
    ldap += b"\x0a\x01\x00"

    # Size limit, time limit
    ldap += b"\x02\x01\x00\x02\x01\x00\x01\x01\x00"

    # Filter (simplified)
    filter_bytes = filter_str.encode()
    ldap += b"\xa3" + bytes([len(filter_bytes)]) + filter_bytes

    # Attributes (empty)
    ldap += b"\x30\x00"

    return ldap


def generate_kerberos_ldap_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate Kerberos and LDAP authentication traffic"""
    logger.info("[+] Generating Kerberos and LDAP traffic...")

    use_serializer = serializer is not None
    packets = []

    current_time = start_time
    auth_count = 0
    target_auths = int(duration * 0.2)  # ~0.2 authentications per second

    while current_time < start_time + duration and auth_count < target_auths:
        # Choose client
        client_ip = random.choice(USER_WORKSTATION_IPS + [SHAREPOINT_SERVER_IP, SQL_SERVER_IP])
        sport = generator.allocate_port(client_ip)

        # Kerberos AS-REQ/AS-REP (port 88)
        if random.random() < 0.5:  # 50% Kerberos
            # AS-REQ
            as_req_payload = generate_kerberos_as_req(client_ip, current_time)
            pkt = Ether(src=generator.mac_table.get(client_ip, "00:00:00:00:00:01"), dst=generator.mac_table.get(DOMAIN_CONTROLLER_IP, "00:00:00:00:00:02"))
            pkt /= IP(src=client_ip, dst=DOMAIN_CONTROLLER_IP)
            pkt /= UDP(sport=sport, dport=88)
            pkt /= Raw(load=as_req_payload)
            pkt.time = current_time
            packets.append(pkt)

            # AS-REP (10-30ms later)
            current_time += random.uniform(0.010, 0.030)
            as_rep_payload = generate_kerberos_as_rep(current_time)
            pkt = Ether(src=generator.mac_table.get(DOMAIN_CONTROLLER_IP, "00:00:00:00:00:02"), dst=generator.mac_table.get(client_ip, "00:00:00:00:00:01"))
            pkt /= IP(src=DOMAIN_CONTROLLER_IP, dst=client_ip)
            pkt /= UDP(sport=88, dport=sport)
            pkt /= Raw(load=as_rep_payload)
            pkt.time = current_time
            packets.append(pkt)

        else:  # 50% LDAP
            # TCP handshake for LDAP
            ldap_packets = tcp_handshake(client_ip, DOMAIN_CONTROLLER_IP, sport, 389, current_time)
            packets.extend(ldap_packets)
            current_time += random_pool.delay_handshake()

            conn = generator.get_connection(client_ip, DOMAIN_CONTROLLER_IP, sport, 389)
            conn_server = generator.get_connection(DOMAIN_CONTROLLER_IP, client_ip, 389, sport)

            # LDAP Bind with REALISTIC USERNAME
            realistic_username = random.choice(REALISTIC_USERNAMES)  # <- jsmith, agarcia, etc
            bind_req = generate_ldap_bind_request(realistic_username)  # <- NOW REALISTIC!
            pkt = create_tcp_psh_ack(client_ip, DOMAIN_CONTROLLER_IP, sport, 389, conn.seq, conn.ack, 65535, bind_req, current_time)
            packets.append(pkt)
            conn.seq += len(bind_req)
            current_time += exponential_delay(0.005, 0.020, 100)

            # LDAP Bind Response (success)
            bind_resp = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"  # Success
            pkt = create_tcp_psh_ack(DOMAIN_CONTROLLER_IP, client_ip, 389, sport, conn_server.seq, conn.seq, 65535, bind_resp, current_time)
            packets.append(pkt)
            conn_server.seq += len(bind_resp)
            conn.ack = conn_server.seq
            current_time += exponential_delay(0.005, 0.020, 100)

            # LDAP Search
            search_filters = ["(objectClass=user)", "(sAMAccountName=user*)", "(objectClass=computer)", "(memberOf=CN=*)"]
            search_req = generate_ldap_search_request("DC=corp,DC=local", random.choice(search_filters))
            pkt = create_tcp_psh_ack(client_ip, DOMAIN_CONTROLLER_IP, sport, 389, conn.seq, conn.ack, 65535, search_req, current_time)
            packets.append(pkt)
            conn.seq += len(search_req)
            current_time += exponential_delay(0.010, 0.050, 50)

            # LDAP Search Response (simplified)
            search_resp = b"\x30\x50" + b"\x00" * 78  # Search result entries
            pkt = create_tcp_psh_ack(DOMAIN_CONTROLLER_IP, client_ip, 389, sport, conn_server.seq, conn.seq, 65535, search_resp, current_time)
            packets.append(pkt)

        auth_count += 1
        current_time += exponential_delay(1, 10, 1)

    logger.info(f"    Kerberos/LDAP traffic: {len(packets)} packets ({auth_count} authentications)")

    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(packets)} Auth packets to PCAP...")
        for pkt in packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return packets  # Return for backward compatibility


__all__ = [
    "generate_kerberos_as_req",
    "generate_kerberos_as_rep",
    "generate_ldap_bind_request",
    "generate_ldap_search_request",
    "generate_kerberos_ldap_traffic",
]
