"""NTP protocol simulation for time synchronization.

NTP (Network Time Protocol) is used for:
- System clock synchronization
- Distributed time coordination
- Network time services
- Stratum-based hierarchical time distribution

RFC 5905 (NTPv4)
"""

from __future__ import annotations

import random
import struct
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet

    from ..serializer import FastPacketSerializer

from ..logging_setup import get_logger
from .base import _emit_packet, _udp_packet

logger = get_logger(__name__)

# NTP Constants
NTP_PORT = 123
NTP_PACKET_SIZE = 48

# NTP Version and Mode
NTP_VERSION = 4  # NTPv4
NTP_MODE_CLIENT = 3
NTP_MODE_SERVER = 4

# NTP Stratum Levels
STRATUM_PRIMARY = 1  # Primary reference (e.g., GPS)
STRATUM_SECONDARY = 2  # Secondary reference (synced to stratum 1)
STRATUM_TERTIARY = 3  # Tertiary reference (synced to stratum 2)

# NTP Timestamp Constants
NTP_EPOCH_OFFSET = 2208988800  # Seconds between 1900 and 1970


def _unix_to_ntp_timestamp(unix_time: float) -> tuple[int, int]:
    """Convert Unix timestamp to NTP timestamp format.

    Args:
        unix_time: Unix timestamp (seconds since 1970)

    Returns:
        Tuple of (seconds, fraction) for NTP timestamp
    """
    ntp_seconds = int(unix_time + NTP_EPOCH_OFFSET)
    fraction = int((unix_time % 1) * 2**32)
    return ntp_seconds, fraction


def _build_ntp_packet(
    mode: int = NTP_MODE_CLIENT,
    stratum: int = 0,
    transmit_timestamp: float | None = None,
    reference_timestamp: float | None = None,
    originate_timestamp: float | None = None,
    receive_timestamp: float | None = None,
) -> bytes:
    """Build an NTPv4 packet.

    Args:
        mode: NTP mode (3=client, 4=server)
        stratum: Stratum level (0 for client, 1-15 for server)
        transmit_timestamp: Time when packet was sent
        reference_timestamp: Last time clock was set
        originate_timestamp: Client's transmit time (from request)
        receive_timestamp: Server's receive time

    Returns:
        48-byte NTP packet
    """
    # Build LI-VN-Mode byte
    leap_indicator = 0  # No warning
    li_vn_mode = (leap_indicator << 6) | (NTP_VERSION << 3) | mode

    # Build packet header
    reference_id = 0x4C4F434C if mode == NTP_MODE_SERVER else 0  # Reference ID ("LOCL" for server)
    packet = struct.pack(
        "!BBBbIII",
        li_vn_mode,  # LI, VN, Mode
        stratum,  # Stratum
        8,  # Poll interval (2^8 = 256 seconds)
        -10,  # Precision (2^-10 ≈ 1ms)
        0,  # Root delay
        0,  # Root dispersion
        reference_id,  # Reference ID
    )

    # Add timestamps
    if reference_timestamp is not None:
        ref_sec, ref_frac = _unix_to_ntp_timestamp(reference_timestamp)
    else:
        ref_sec, ref_frac = 0, 0

    if originate_timestamp is not None:
        orig_sec, orig_frac = _unix_to_ntp_timestamp(originate_timestamp)
    else:
        orig_sec, orig_frac = 0, 0

    if receive_timestamp is not None:
        recv_sec, recv_frac = _unix_to_ntp_timestamp(receive_timestamp)
    else:
        recv_sec, recv_frac = 0, 0

    if transmit_timestamp is not None:
        trans_sec, trans_frac = _unix_to_ntp_timestamp(transmit_timestamp)
    else:
        trans_sec, trans_frac = 0, 0

    # Pack all timestamps (each is 8 bytes: 4 bytes seconds + 4 bytes fraction)
    packet += struct.pack("!II", ref_sec, ref_frac)  # Reference timestamp
    packet += struct.pack("!II", orig_sec, orig_frac)  # Originate timestamp
    packet += struct.pack("!II", recv_sec, recv_frac)  # Receive timestamp
    packet += struct.pack("!II", trans_sec, trans_frac)  # Transmit timestamp

    return packet


def generate_ntp_query(
    client_ip: str,
    ntp_server: str,
    start_time: float,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate NTP client query packet.

    Simulates NTP client request without response.

    Args:
        client_ip: Client IP address
        ntp_server: NTP server IP
        start_time: Timestamp for packet
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    sport = random.randint(1024, 65535)

    # Client request with transmit timestamp
    request_payload = _build_ntp_packet(
        mode=NTP_MODE_CLIENT,
        stratum=0,  # Unspecified for client
        transmit_timestamp=start_time,
    )

    request_pkt = _udp_packet(client_ip, ntp_server, sport, NTP_PORT, request_payload, start_time)
    _emit_packet(serializer, packets, request_pkt, start_time)

    return packets if serializer is None else []


def generate_ntp_response(
    client_ip: str,
    ntp_server: str,
    start_time: float,
    stratum: int = STRATUM_SECONDARY,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate NTP query/response exchange.

    Simulates complete NTP request → response flow.

    Args:
        client_ip: Client IP address
        ntp_server: NTP server IP
        start_time: Timestamp for first packet
        stratum: Server stratum level (1=primary, 2=secondary, etc.)
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    current_time = start_time
    sport = random.randint(1024, 65535)

    # Client request
    client_transmit_time = current_time
    request_payload = _build_ntp_packet(
        mode=NTP_MODE_CLIENT,
        stratum=0,
        transmit_timestamp=client_transmit_time,
    )
    request_pkt = _udp_packet(client_ip, ntp_server, sport, NTP_PORT, request_payload, current_time)
    _emit_packet(serializer, packets, request_pkt, current_time)

    # Network delay (0.5-5ms typical for local NTP)
    current_time += random.uniform(0.0005, 0.005)

    # Server response
    server_receive_time = current_time
    server_transmit_time = current_time + 0.0001  # Minimal processing time
    reference_time = current_time - random.uniform(60, 300)  # Last sync 1-5 min ago

    response_payload = _build_ntp_packet(
        mode=NTP_MODE_SERVER,
        stratum=stratum,
        transmit_timestamp=server_transmit_time,
        reference_timestamp=reference_time,
        originate_timestamp=client_transmit_time,  # Echo client's transmit
        receive_timestamp=server_receive_time,
    )

    response_pkt = _udp_packet(ntp_server, client_ip, NTP_PORT, sport, response_payload, server_transmit_time)
    _emit_packet(serializer, packets, response_pkt, server_transmit_time)

    return packets if serializer is None else []


def generate_ntp_background_polling(
    client_ip: str,
    ntp_server: str,
    start_time: float,
    duration: float,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate background NTP polling traffic.

    Simulates periodic NTP synchronization (typical: every 64-1024 seconds).

    Args:
        client_ip: Client IP address
        ntp_server: NTP server IP
        start_time: Start timestamp
        duration: Duration to generate traffic (seconds)
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    current_time = start_time

    while current_time < start_time + duration:
        # Generate query/response
        poll_packets = generate_ntp_response(client_ip, ntp_server, current_time, serializer=serializer)
        if serializer is None:
            packets.extend(poll_packets)

        # NTP poll interval: 64-1024 seconds (2^6 to 2^10)
        poll_interval = random.uniform(64, 1024)
        current_time += poll_interval

    return packets if serializer is None else []


def generate_ntp_pool_queries(
    client_ip: str,
    pool_servers: list[str] | None = None,
    start_time: float = None,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate NTP queries to pool.ntp.org style servers.

    Simulates client querying multiple NTP pool servers for redundancy.

    Args:
        client_ip: Client IP address
        pool_servers: List of NTP server IPs (defaults to 4 servers)
        start_time: Start timestamp
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    if start_time is None:
        start_time = time.time()

    if pool_servers is None:
        # Simulate pool.ntp.org DNS resolution to 4 servers
        pool_servers = [
            "129.6.15.28",  # time.nist.gov
            "132.163.96.1",  # time-a.nist.gov
            "129.6.15.29",  # time.nist.gov
            "132.163.97.1",  # time-b.nist.gov
        ]

    packets: list[Packet] = []
    current_time = start_time

    # Query each pool server with slight delay
    for server in pool_servers:
        server_packets = generate_ntp_response(client_ip, server, current_time, stratum=STRATUM_PRIMARY, serializer=serializer)
        if serializer is None:
            packets.extend(server_packets)

        # Small delay between queries (100-500ms)
        current_time += random.uniform(0.1, 0.5)

    return packets if serializer is None else []


__all__ = [
    "NTP_PORT",
    "NTP_VERSION",
    "STRATUM_PRIMARY",
    "STRATUM_SECONDARY",
    "STRATUM_TERTIARY",
    "generate_ntp_query",
    "generate_ntp_response",
    "generate_ntp_background_polling",
    "generate_ntp_pool_queries",
]
