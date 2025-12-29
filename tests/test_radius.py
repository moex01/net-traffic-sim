"""Tests for RADIUS protocol simulation."""

from __future__ import annotations

import time
from io import BytesIO

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from net_traffic_sim.protocols.radius import (
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_CHALLENGE,
    RADIUS_ACCESS_REJECT,
    RADIUS_ACCESS_REQUEST,
    RADIUS_ACCOUNTING_REQUEST,
    RADIUS_ACCOUNTING_RESPONSE,
    RADIUS_ACCT_PORT,
    RADIUS_AUTH_PORT,
    generate_radius_accounting,
    generate_radius_auth_failure,
    generate_radius_auth_success,
    generate_radius_mfa_flow,
    generate_radius_vpn_auth,
    generate_radius_wifi_auth,
)
from net_traffic_sim.serializer import FastPacketSerializer


class TestRADIUSAuthSuccess:
    """Test successful RADIUS authentication flow."""

    def test_generate_radius_auth_success_basic(self):
        """Test basic successful RADIUS authentication."""
        src_ip = "10.1.1.100"
        radius_server = "10.1.1.10"
        username = "john.doe"
        start_time = time.time()

        packets = generate_radius_auth_success(src_ip, radius_server, username, start_time)

        # Should have request + response
        assert len(packets) == 2, "Should have Access-Request and Access-Accept"

        # Verify first packet is Access-Request
        request = packets[0]
        assert IP in request
        assert UDP in request
        assert request[IP].src == src_ip
        assert request[IP].dst == radius_server
        assert request[UDP].dport == RADIUS_AUTH_PORT

        # Verify RADIUS packet structure
        assert Raw in request
        radius_payload = request[Raw].load
        assert len(radius_payload) >= 20, "RADIUS packet too short"
        assert radius_payload[0] == RADIUS_ACCESS_REQUEST, "Should be Access-Request"

        # Verify second packet is Access-Accept
        response = packets[1]
        assert IP in response
        assert response[IP].src == radius_server
        assert response[IP].dst == src_ip
        assert response[UDP].sport == RADIUS_AUTH_PORT

        radius_response = response[Raw].load
        assert radius_response[0] == RADIUS_ACCESS_ACCEPT, "Should be Access-Accept"

    def test_radius_auth_success_identifiers_match(self):
        """Test that request and response identifiers match."""
        packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", "user", time.time())

        request_id = packets[0][Raw].load[1]
        response_id = packets[1][Raw].load[1]

        assert request_id == response_id, "Request and response identifiers should match"

    def test_radius_auth_success_with_serializer(self):
        """Test RADIUS auth with serializer."""
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=10) as serializer:
            packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", "user", time.time(), serializer=serializer)

            assert len(packets) == 0, "Should return empty list with serializer"
            assert serializer.packet_count == 2, "Serializer should have 2 packets"


class TestRADIUSAuthFailure:
    """Test failed RADIUS authentication flow."""

    def test_generate_radius_auth_failure_basic(self):
        """Test basic failed RADIUS authentication."""
        src_ip = "10.1.1.100"
        radius_server = "10.1.1.10"
        username = "invalid.user"
        start_time = time.time()

        packets = generate_radius_auth_failure(src_ip, radius_server, username, start_time)

        # Should have request + reject
        assert len(packets) == 2, "Should have Access-Request and Access-Reject"

        # Verify Access-Request
        request = packets[0]
        assert request[IP].src == src_ip
        assert request[IP].dst == radius_server
        assert request[UDP].dport == RADIUS_AUTH_PORT

        radius_request = request[Raw].load
        assert radius_request[0] == RADIUS_ACCESS_REQUEST

        # Verify Access-Reject
        response = packets[1]
        assert response[IP].src == radius_server
        assert response[IP].dst == src_ip

        radius_response = response[Raw].load
        assert radius_response[0] == RADIUS_ACCESS_REJECT, "Should be Access-Reject"

    def test_radius_auth_failure_contains_reply_message(self):
        """Test that Access-Reject contains reply message attribute."""
        packets = generate_radius_auth_failure("10.1.1.100", "10.1.1.10", "baduser", time.time())

        reject_packet = packets[1]
        radius_payload = reject_packet[Raw].load

        # Check for reply message in attributes (should contain "Invalid")
        assert b"Invalid" in radius_payload, "Should have error message"


class TestRADIUSMFA:
    """Test RADIUS multi-factor authentication flow."""

    def test_generate_radius_mfa_flow_basic(self):
        """Test basic MFA flow with Access-Challenge."""
        src_ip = "10.1.1.100"
        radius_server = "10.1.1.10"
        username = "admin"
        start_time = time.time()

        packets = generate_radius_mfa_flow(src_ip, radius_server, username, start_time)

        # Should have 4 packets: Request → Challenge → Request → Accept
        assert len(packets) == 4, "MFA flow should have 4 packets"

        # Verify first Access-Request
        assert packets[0][Raw].load[0] == RADIUS_ACCESS_REQUEST

        # Verify Access-Challenge
        challenge = packets[1]
        assert challenge[IP].src == radius_server
        radius_challenge = challenge[Raw].load
        assert radius_challenge[0] == RADIUS_ACCESS_CHALLENGE, "Should be Access-Challenge"

        # Verify second Access-Request
        assert packets[2][Raw].load[0] == RADIUS_ACCESS_REQUEST

        # Verify final Access-Accept
        assert packets[3][Raw].load[0] == RADIUS_ACCESS_ACCEPT

    def test_radius_mfa_flow_state_attribute(self):
        """Test that Access-Challenge includes State attribute."""
        packets = generate_radius_mfa_flow("10.1.1.100", "10.1.1.10", "admin", time.time())

        challenge_packet = packets[1]
        challenge_payload = challenge_packet[Raw].load

        # State attribute should be present (type 24)
        # This is a simplified check - real implementation would parse attributes
        assert len(challenge_payload) > 20, "Challenge should have State attribute"

    def test_radius_mfa_timing_realistic(self):
        """Test that MFA flow has realistic timing between packets."""
        start = time.time()
        packets = generate_radius_mfa_flow("10.1.1.100", "10.1.1.10", "admin", start)

        # Check timestamps
        timestamps = [p.time for p in packets]

        # First 2 packets should be close together (< 1 second)
        assert timestamps[1] - timestamps[0] < 1.0, "Challenge should come quickly"

        # Third packet should be delayed (user entering MFA token)
        assert timestamps[2] - timestamps[1] > 4.0, "User MFA entry should take time"


class TestRADIUSAccounting:
    """Test RADIUS accounting flows."""

    def test_generate_radius_accounting_start(self):
        """Test RADIUS accounting start."""
        src_ip = "10.1.1.100"
        radius_server = "10.1.1.10"
        session_id = "session-12345"
        start_time = time.time()

        packets = generate_radius_accounting(src_ip, radius_server, session_id, start_time, acct_type="start")

        # Should have accounting request + response
        assert len(packets) == 2, "Should have Accounting-Request and Accounting-Response"

        # Verify Accounting-Request
        request = packets[0]
        assert request[IP].src == src_ip
        assert request[IP].dst == radius_server
        assert request[UDP].dport == RADIUS_ACCT_PORT, "Should use accounting port 1813"

        radius_request = request[Raw].load
        assert radius_request[0] == RADIUS_ACCOUNTING_REQUEST

        # Verify Accounting-Response
        response = packets[1]
        assert response[IP].src == radius_server
        assert response[UDP].sport == RADIUS_ACCT_PORT

        radius_response = response[Raw].load
        assert radius_response[0] == RADIUS_ACCOUNTING_RESPONSE

    def test_radius_accounting_stop(self):
        """Test RADIUS accounting stop."""
        packets = generate_radius_accounting("10.1.1.100", "10.1.1.10", "session-999", time.time(), acct_type="stop")

        assert len(packets) == 2, "Should have request/response"
        # Accounting stop should have status type 2
        # (detailed attribute parsing would verify this)

    def test_radius_accounting_interim_update(self):
        """Test RADIUS accounting interim update."""
        packets = generate_radius_accounting("10.1.1.100", "10.1.1.10", "session-111", time.time(), acct_type="interim-update")

        assert len(packets) == 2, "Should have request/response"


class TestRADIUSWiFiAuth:
    """Test WiFi authentication via RADIUS."""

    def test_generate_radius_wifi_auth_success(self):
        """Test successful WiFi authentication."""
        ap_ip = "10.1.1.50"
        radius_server = "10.1.1.10"
        username = "wifi-user"
        start_time = time.time()

        packets = generate_radius_wifi_auth(ap_ip, radius_server, username, start_time, success=True)

        # Should be same as basic auth success
        assert len(packets) == 2, "Should have request/accept"
        assert packets[0][IP].src == ap_ip, "Should come from AP"
        assert packets[1][Raw].load[0] == RADIUS_ACCESS_ACCEPT

    def test_radius_wifi_auth_failure(self):
        """Test failed WiFi authentication."""
        packets = generate_radius_wifi_auth("10.1.1.50", "10.1.1.10", "baduser", time.time(), success=False)

        assert len(packets) == 2, "Should have request/reject"
        assert packets[1][Raw].load[0] == RADIUS_ACCESS_REJECT

    def test_radius_wifi_auth_uses_correct_port(self):
        """Test that WiFi auth uses RADIUS auth port."""
        packets = generate_radius_wifi_auth("10.1.1.50", "10.1.1.10", "user", time.time())

        assert packets[0][UDP].dport == RADIUS_AUTH_PORT, "Should use port 1812"


class TestRADIUSVPNAuth:
    """Test VPN authentication via RADIUS."""

    def test_generate_radius_vpn_auth_basic(self):
        """Test basic VPN authentication without MFA."""
        vpn_gateway = "10.1.1.200"
        radius_server = "10.1.1.10"
        username = "vpn-user"
        start_time = time.time()

        packets = generate_radius_vpn_auth(vpn_gateway, radius_server, username, start_time, use_mfa=False)

        # Should be simple success flow
        assert len(packets) == 2, "Should have request/accept"
        assert packets[0][IP].src == vpn_gateway, "Should come from VPN gateway"
        assert packets[1][Raw].load[0] == RADIUS_ACCESS_ACCEPT

    def test_radius_vpn_auth_with_mfa(self):
        """Test VPN authentication with MFA."""
        packets = generate_radius_vpn_auth("10.1.1.200", "10.1.1.10", "vpn-admin", time.time(), use_mfa=True)

        # Should be full MFA flow
        assert len(packets) == 4, "MFA should have 4 packets"
        assert packets[1][Raw].load[0] == RADIUS_ACCESS_CHALLENGE, "Should have Challenge"

    def test_radius_vpn_auth_packet_structure(self):
        """Test VPN auth packet structure."""
        packets = generate_radius_vpn_auth("10.1.1.200", "10.1.1.10", "user", time.time())

        for packet in packets:
            # All packets should have proper layers
            assert Ether in packet, "Should have Ethernet layer"
            assert IP in packet, "Should have IP layer"
            assert UDP in packet, "Should have UDP layer"
            assert Raw in packet, "Should have RADIUS payload"


class TestRADIUSPacketStructure:
    """Test RADIUS packet structure and format."""

    def test_radius_packet_minimum_length(self):
        """Test that RADIUS packets meet minimum length requirement."""
        packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", "user", time.time())

        for packet in packets:
            radius_payload = packet[Raw].load
            # RADIUS packets must be at least 20 bytes (header)
            assert len(radius_payload) >= 20, "RADIUS packet too short"

    def test_radius_packet_has_authenticator(self):
        """Test that RADIUS packets include 16-byte authenticator."""
        packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", "user", time.time())

        for packet in packets:
            radius_payload = packet[Raw].load
            # Authenticator is bytes 4-19 (16 bytes)
            authenticator = radius_payload[4:20]
            assert len(authenticator) == 16, "Authenticator must be 16 bytes"

    def test_radius_packet_length_field(self):
        """Test that RADIUS packet length field is correct."""
        packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", "user", time.time())

        for packet in packets:
            radius_payload = packet[Raw].load
            # Length field is bytes 2-3 (big-endian uint16)
            length_field = int.from_bytes(radius_payload[2:4], byteorder="big")
            actual_length = len(radius_payload)
            assert length_field == actual_length, "Length field should match actual packet length"


class TestRADIUSEdgeCases:
    """Test edge cases and error scenarios."""

    def test_radius_with_long_username(self):
        """Test RADIUS with very long username."""
        long_username = "a" * 200
        packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", long_username, time.time())

        assert len(packets) == 2, "Should handle long username"
        # Username should be in the packet
        assert long_username.encode() in packets[0][Raw].load

    def test_radius_with_special_characters_username(self):
        """Test RADIUS with special characters in username."""
        special_username = "user@domain.com"
        packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", special_username, time.time())

        assert len(packets) == 2, "Should handle special characters"

    def test_radius_accounting_invalid_type(self):
        """Test accounting with invalid type defaults to start."""
        packets = generate_radius_accounting("10.1.1.100", "10.1.1.10", "session-1", time.time(), acct_type="invalid")

        # Should default to "start" type
        assert len(packets) == 2, "Should still generate packets"

    def test_radius_timestamps_sequential(self):
        """Test that RADIUS packet timestamps are sequential."""
        packets = generate_radius_auth_success("10.1.1.100", "10.1.1.10", "user", time.time())

        timestamps = [p.time for p in packets]
        assert timestamps[1] > timestamps[0], "Response should come after request"
        assert timestamps[1] - timestamps[0] < 1.0, "Response should be quick"
