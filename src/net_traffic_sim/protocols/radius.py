"""RADIUS protocol simulation for enterprise authentication.

RADIUS (Remote Authentication Dial-In User Service) is used for:
- WiFi authentication (WPA2-Enterprise)
- VPN user authentication
- Network access control (802.1X)
- Accounting and session management

RFC 2865 (RADIUS Auth) and RFC 2866 (RADIUS Accounting)
"""

from __future__ import annotations

import random
import secrets
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet

    from ..serializer import FastPacketSerializer

from ..logging_setup import get_logger
from .base import _emit_packet, _udp_packet

logger = get_logger(__name__)

# RADIUS Constants
RADIUS_AUTH_PORT = 1812
RADIUS_ACCT_PORT = 1813

# RADIUS Packet Codes (RFC 2865)
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_ACCESS_CHALLENGE = 11

# RADIUS Attribute Types (RFC 2865)
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_FRAMED_IP_ADDRESS = 8
ATTR_REPLY_MESSAGE = 18
ATTR_STATE = 24
ATTR_CLASS = 25
ATTR_SESSION_TIMEOUT = 27
ATTR_ACCT_STATUS_TYPE = 40
ATTR_ACCT_SESSION_ID = 44


def _build_radius_packet(
    code: int,
    identifier: int,
    attributes: list[tuple[int, bytes]],
    authenticator: bytes | None = None,
) -> bytes:
    """Build a RADIUS packet with specified code and attributes.

    Args:
        code: RADIUS packet code (ACCESS_REQUEST, ACCESS_ACCEPT, etc.)
        identifier: Packet identifier (0-255)
        attributes: List of (attribute_type, attribute_value) tuples
        authenticator: 16-byte authenticator (generated if None)

    Returns:
        Complete RADIUS packet as bytes
    """
    if authenticator is None:
        authenticator = secrets.token_bytes(16)

    # Build attributes section
    attr_data = b""
    for attr_type, attr_value in attributes:
        attr_len = len(attr_value) + 2  # Type (1) + Length (1) + Value
        attr_data += struct.pack("!BB", attr_type, attr_len) + attr_value

    # Build RADIUS header
    packet_length = 20 + len(attr_data)  # Header (20) + Attributes
    packet = struct.pack("!BBH", code, identifier, packet_length)
    packet += authenticator
    packet += attr_data

    return packet


def generate_radius_auth_success(
    src_ip: str,
    radius_server: str,
    username: str,
    start_time: float,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate successful RADIUS authentication flow.

    Simulates Access-Request → Access-Accept flow.

    Args:
        src_ip: Client IP address (NAS/AP)
        radius_server: RADIUS server IP
        username: Username attempting authentication
        start_time: Timestamp for first packet
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    current_time = start_time
    identifier = random.randint(0, 255)
    sport = random.randint(1024, 65535)

    # Access-Request
    request_attrs = [
        (ATTR_USER_NAME, username.encode()),
        (ATTR_USER_PASSWORD, b"\x00" * 16),  # Encrypted password
        (ATTR_NAS_IP_ADDRESS, bytes(map(int, src_ip.split(".")))),
        (ATTR_NAS_PORT, struct.pack("!I", random.randint(0, 255))),
    ]
    request_payload = _build_radius_packet(RADIUS_ACCESS_REQUEST, identifier, request_attrs)
    request_pkt = _udp_packet(src_ip, radius_server, sport, RADIUS_AUTH_PORT, request_payload, current_time)
    _emit_packet(serializer, packets, request_pkt, current_time)

    current_time += random.uniform(0.001, 0.010)

    # Access-Accept
    accept_attrs = [
        (ATTR_FRAMED_IP_ADDRESS, bytes([10, 0, random.randint(0, 255), random.randint(1, 254)])),
        (ATTR_SESSION_TIMEOUT, struct.pack("!I", 3600)),  # 1 hour session
        (ATTR_CLASS, b"premium-user"),
    ]
    accept_payload = _build_radius_packet(RADIUS_ACCESS_ACCEPT, identifier, accept_attrs)
    accept_pkt = _udp_packet(radius_server, src_ip, RADIUS_AUTH_PORT, sport, accept_payload, current_time)
    _emit_packet(serializer, packets, accept_pkt, current_time)

    return packets if serializer is None else []


def generate_radius_auth_failure(
    src_ip: str,
    radius_server: str,
    username: str,
    start_time: float,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate failed RADIUS authentication flow.

    Simulates Access-Request → Access-Reject flow.

    Args:
        src_ip: Client IP address (NAS/AP)
        radius_server: RADIUS server IP
        username: Username attempting authentication
        start_time: Timestamp for first packet
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    current_time = start_time
    identifier = random.randint(0, 255)
    sport = random.randint(1024, 65535)

    # Access-Request
    request_attrs = [
        (ATTR_USER_NAME, username.encode()),
        (ATTR_USER_PASSWORD, b"\x00" * 16),  # Invalid password
        (ATTR_NAS_IP_ADDRESS, bytes(map(int, src_ip.split(".")))),
    ]
    request_payload = _build_radius_packet(RADIUS_ACCESS_REQUEST, identifier, request_attrs)
    request_pkt = _udp_packet(src_ip, radius_server, sport, RADIUS_AUTH_PORT, request_payload, current_time)
    _emit_packet(serializer, packets, request_pkt, current_time)

    current_time += random.uniform(0.001, 0.010)

    # Access-Reject
    reject_attrs = [(ATTR_REPLY_MESSAGE, b"Invalid credentials")]
    reject_payload = _build_radius_packet(RADIUS_ACCESS_REJECT, identifier, reject_attrs)
    reject_pkt = _udp_packet(radius_server, src_ip, RADIUS_AUTH_PORT, sport, reject_payload, current_time)
    _emit_packet(serializer, packets, reject_pkt, current_time)

    return packets if serializer is None else []


def generate_radius_mfa_flow(
    src_ip: str,
    radius_server: str,
    username: str,
    start_time: float,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate RADIUS multi-factor authentication flow.

    Simulates Access-Request → Access-Challenge → Access-Request → Access-Accept.

    Args:
        src_ip: Client IP address (NAS/AP)
        radius_server: RADIUS server IP
        username: Username attempting authentication
        start_time: Timestamp for first packet
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    current_time = start_time
    identifier = random.randint(0, 255)
    sport = random.randint(1024, 65535)
    state_value = secrets.token_bytes(16)

    # Initial Access-Request (username + password)
    request1_attrs = [
        (ATTR_USER_NAME, username.encode()),
        (ATTR_USER_PASSWORD, b"\x00" * 16),
        (ATTR_NAS_IP_ADDRESS, bytes(map(int, src_ip.split(".")))),
    ]
    request1_payload = _build_radius_packet(RADIUS_ACCESS_REQUEST, identifier, request1_attrs)
    request1_pkt = _udp_packet(src_ip, radius_server, sport, RADIUS_AUTH_PORT, request1_payload, current_time)
    _emit_packet(serializer, packets, request1_pkt, current_time)

    current_time += random.uniform(0.001, 0.010)

    # Access-Challenge (request MFA token)
    challenge_attrs = [
        (ATTR_REPLY_MESSAGE, b"Enter MFA token:"),
        (ATTR_STATE, state_value),
    ]
    challenge_payload = _build_radius_packet(RADIUS_ACCESS_CHALLENGE, identifier, challenge_attrs)
    challenge_pkt = _udp_packet(radius_server, src_ip, RADIUS_AUTH_PORT, sport, challenge_payload, current_time)
    _emit_packet(serializer, packets, challenge_pkt, current_time)

    current_time += random.uniform(5.0, 10.0)  # User enters MFA token

    # Second Access-Request (with MFA token + state)
    identifier2 = (identifier + 1) % 256
    request2_attrs = [
        (ATTR_USER_NAME, username.encode()),
        (ATTR_USER_PASSWORD, b"123456"),  # MFA token
        (ATTR_STATE, state_value),
        (ATTR_NAS_IP_ADDRESS, bytes(map(int, src_ip.split(".")))),
    ]
    request2_payload = _build_radius_packet(RADIUS_ACCESS_REQUEST, identifier2, request2_attrs)
    request2_pkt = _udp_packet(src_ip, radius_server, sport, RADIUS_AUTH_PORT, request2_payload, current_time)
    _emit_packet(serializer, packets, request2_pkt, current_time)

    current_time += random.uniform(0.001, 0.010)

    # Access-Accept
    accept_attrs = [
        (ATTR_FRAMED_IP_ADDRESS, bytes([10, 0, random.randint(0, 255), random.randint(1, 254)])),
        (ATTR_SESSION_TIMEOUT, struct.pack("!I", 3600)),
    ]
    accept_payload = _build_radius_packet(RADIUS_ACCESS_ACCEPT, identifier2, accept_attrs)
    accept_pkt = _udp_packet(radius_server, src_ip, RADIUS_AUTH_PORT, sport, accept_payload, current_time)
    _emit_packet(serializer, packets, accept_pkt, current_time)

    return packets if serializer is None else []


def generate_radius_accounting(
    src_ip: str,
    radius_server: str,
    session_id: str,
    start_time: float,
    acct_type: str = "start",
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate RADIUS accounting request/response.

    Simulates Accounting-Request → Accounting-Response flow.

    Args:
        src_ip: Client IP address (NAS/AP)
        radius_server: RADIUS server IP
        session_id: Session identifier
        start_time: Timestamp for first packet
        acct_type: Accounting type ("start", "stop", "interim-update")
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    current_time = start_time
    identifier = random.randint(0, 255)
    sport = random.randint(1024, 65535)

    # Map accounting type to status code
    status_codes = {"start": 1, "stop": 2, "interim-update": 3}
    status_code = status_codes.get(acct_type, 1)

    # Accounting-Request
    acct_attrs = [
        (ATTR_ACCT_STATUS_TYPE, struct.pack("!I", status_code)),
        (ATTR_ACCT_SESSION_ID, session_id.encode()),
        (ATTR_USER_NAME, b"user@example.com"),
        (ATTR_NAS_IP_ADDRESS, bytes(map(int, src_ip.split(".")))),
    ]
    acct_payload = _build_radius_packet(RADIUS_ACCOUNTING_REQUEST, identifier, acct_attrs)
    acct_pkt = _udp_packet(src_ip, radius_server, sport, RADIUS_ACCT_PORT, acct_payload, current_time)
    _emit_packet(serializer, packets, acct_pkt, current_time)

    current_time += random.uniform(0.001, 0.005)

    # Accounting-Response
    response_payload = _build_radius_packet(RADIUS_ACCOUNTING_RESPONSE, identifier, [])
    response_pkt = _udp_packet(radius_server, src_ip, RADIUS_ACCT_PORT, sport, response_payload, current_time)
    _emit_packet(serializer, packets, response_pkt, current_time)

    return packets if serializer is None else []


def generate_radius_wifi_auth(
    ap_ip: str,
    radius_server: str,
    username: str,
    start_time: float,
    success: bool = True,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate RADIUS authentication for WPA2-Enterprise WiFi.

    Simulates 802.1X/EAP authentication via RADIUS.

    Args:
        ap_ip: Access Point IP address
        radius_server: RADIUS server IP
        username: WiFi username
        start_time: Timestamp for first packet
        success: Whether authentication succeeds
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    if success:
        return generate_radius_auth_success(ap_ip, radius_server, username, start_time, serializer)
    else:
        return generate_radius_auth_failure(ap_ip, radius_server, username, start_time, serializer)


def generate_radius_vpn_auth(
    vpn_gateway: str,
    radius_server: str,
    username: str,
    start_time: float,
    use_mfa: bool = False,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate RADIUS authentication for VPN access.

    Simulates VPN gateway authenticating user via RADIUS.

    Args:
        vpn_gateway: VPN gateway IP address
        radius_server: RADIUS server IP
        username: VPN username
        start_time: Timestamp for first packet
        use_mfa: Whether to use multi-factor authentication
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    if use_mfa:
        return generate_radius_mfa_flow(vpn_gateway, radius_server, username, start_time, serializer)
    else:
        return generate_radius_auth_success(vpn_gateway, radius_server, username, start_time, serializer)


__all__ = [
    "RADIUS_AUTH_PORT",
    "RADIUS_ACCT_PORT",
    "RADIUS_ACCESS_REQUEST",
    "RADIUS_ACCESS_ACCEPT",
    "RADIUS_ACCESS_REJECT",
    "RADIUS_ACCOUNTING_REQUEST",
    "RADIUS_ACCOUNTING_RESPONSE",
    "RADIUS_ACCESS_CHALLENGE",
    "generate_radius_auth_success",
    "generate_radius_auth_failure",
    "generate_radius_mfa_flow",
    "generate_radius_accounting",
    "generate_radius_wifi_auth",
    "generate_radius_vpn_auth",
]
