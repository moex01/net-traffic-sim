"""Tests for authentication protocols in sharepoint.py.

This module tests:
- Kerberos AS-REQ/AS-REP generation
- LDAP bind and search operations
- RDP session establishment and data exchange
- NTLM authentication flows
"""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from net_traffic_sim.protocols.sharepoint import (
    generate_kerberos_as_rep,
    generate_kerberos_as_req,
    generate_kerberos_ldap_traffic,
    generate_ldap_bind_request,
    generate_ldap_search_request,
    generate_rdp_application_data,
    generate_rdp_session,
    generate_rdp_traffic,
)
from net_traffic_sim.serializer import FastPacketSerializer

# =============================================================================
# Kerberos Tests
# =============================================================================


class TestKerberos:
    """Test Kerberos authentication protocol generation."""

    def test_kerberos_as_req_structure(self):
        """Test Kerberos AS-REQ packet structure."""
        timestamp = 1234567890.0
        as_req = generate_kerberos_as_req("10.0.0.1", timestamp)

        # Verify it's bytes
        assert isinstance(as_req, bytes)

        # Verify Kerberos application tag (0x6a for AS-REQ)
        assert as_req[0:1] == b"\x6a"

        # Verify minimum realistic size (padded to 200 bytes)
        assert len(as_req) >= 200

        # Verify realm is present
        assert b"CORP.LOCAL" in as_req

        # Verify krbtgt service principal
        assert b"krbtgt" in as_req

    def test_kerberos_as_req_username_extraction(self):
        """Test that username is properly extracted from tuple."""
        timestamp = 1234567890.0

        # Generate multiple AS-REQs to ensure consistent behavior
        for _ in range(10):
            as_req = generate_kerberos_as_req("10.0.0.1", timestamp)

            # Should not contain full email or full name (only username)
            assert b"@corp.local" not in as_req.lower()
            assert b" " not in as_req[:100]  # No spaces in username section

    def test_kerberos_as_rep_structure(self):
        """Test Kerberos AS-REP packet structure."""
        timestamp = 1234567890.0
        as_rep = generate_kerberos_as_rep(timestamp)

        # Verify it's bytes
        assert isinstance(as_rep, bytes)

        # Verify Kerberos application tag (0x6b for AS-REP)
        assert as_rep[0:1] == b"\x6b"

        # Verify minimum size (includes encrypted TGT)
        assert len(as_rep) >= 300

    def test_kerberos_as_rep_contains_tgt(self):
        """Test that AS-REP contains encrypted ticket (TGT)."""
        timestamp = 1234567890.0
        as_rep = generate_kerberos_as_rep(timestamp)

        # Verify ticket section (APPLICATION 1 tag = 0x61)
        assert b"\x61" in as_rep

    def test_kerberos_traffic_generation(self):
        """Test complete Kerberos traffic generation."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Should generate some Kerberos packets
        assert len(packets) > 0

        # Find Kerberos packets (UDP port 88)
        kerberos_packets = [pkt for pkt in packets if UDP in pkt and (pkt[UDP].sport == 88 or pkt[UDP].dport == 88)]
        assert len(kerberos_packets) > 0

    def test_kerberos_as_exchange(self):
        """Test Kerberos AS-REQ/AS-REP exchange pattern."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Find Kerberos request/response pairs
        kerberos_packets = [pkt for pkt in packets if UDP in pkt and (pkt[UDP].sport == 88 or pkt[UDP].dport == 88)]

        if len(kerberos_packets) >= 2:
            # Check request-response pattern
            req = kerberos_packets[0]
            rep = kerberos_packets[1]

            # Request should be to DC on port 88
            assert req[UDP].dport == 88

            # Response should be from DC port 88
            assert rep[UDP].sport == 88

            # Response should come after request
            assert rep.time > req.time

    def test_kerberos_timing(self):
        """Test Kerberos AS-REP timing (10-30ms after AS-REQ)."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Find Kerberos request/response pairs
        kerberos_packets = [pkt for pkt in packets if UDP in pkt and (pkt[UDP].sport == 88 or pkt[UDP].dport == 88)]

        if len(kerberos_packets) >= 2:
            req = kerberos_packets[0]
            rep = kerberos_packets[1]

            # Response should be 10-30ms after request
            delay = rep.time - req.time
            assert 0.010 <= delay <= 0.050  # Allow some tolerance


# =============================================================================
# LDAP Tests
# =============================================================================


class TestLDAP:
    """Test LDAP authentication and directory operations."""

    def test_ldap_bind_request_structure(self):
        """Test LDAP bind request structure."""
        username = "jsmith"
        bind_req = generate_ldap_bind_request(username)

        # Verify it's bytes
        assert isinstance(bind_req, bytes)

        # Verify LDAP SEQUENCE tag (0x30)
        assert bind_req[0:1] == b"\x30"

        # Verify bind request APPLICATION tag (0x60)
        assert b"\x60" in bind_req

        # Verify username is in CORP\username format
        expected_dn = f"CORP\\{username}".encode()
        assert expected_dn in bind_req

        # Verify LDAP version 3
        assert b"\x02\x01\x03" in bind_req

    def test_ldap_bind_request_simple_auth(self):
        """Test LDAP bind uses simple authentication."""
        username = "testuser"
        bind_req = generate_ldap_bind_request(username)

        # Verify simple authentication tag (0x80) and password
        assert b"\x80\x08password" in bind_req

    def test_ldap_search_request_structure(self):
        """Test LDAP search request structure."""
        base_dn = "DC=corp,DC=local"
        filter_str = "(objectClass=user)"

        search_req = generate_ldap_search_request(base_dn, filter_str)

        # Verify it's bytes
        assert isinstance(search_req, bytes)

        # Verify LDAP SEQUENCE tag
        assert search_req[0:1] == b"\x30"

        # Verify search request APPLICATION tag (0x63)
        assert b"\x63" in search_req

        # Verify base DN is present
        assert base_dn.encode() in search_req

        # Verify filter is present
        assert filter_str.encode() in search_req

    def test_ldap_search_request_scope(self):
        """Test LDAP search request has wholeSubtree scope."""
        base_dn = "DC=corp,DC=local"
        filter_str = "(cn=*)"

        search_req = generate_ldap_search_request(base_dn, filter_str)

        # Verify wholeSubtree scope (0x0a 0x01 0x02)
        assert b"\x0a\x01\x02" in search_req

    def test_ldap_traffic_generation(self):
        """Test complete LDAP traffic generation."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Should generate some packets
        assert len(packets) > 0

        # Find LDAP packets (TCP port 389)
        ldap_packets = [pkt for pkt in packets if TCP in pkt and (pkt[TCP].sport == 389 or pkt[TCP].dport == 389)]

        # Should have some LDAP traffic
        assert len(ldap_packets) > 0

    def test_ldap_tcp_handshake(self):
        """Test LDAP connections use proper TCP handshake."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Find LDAP packets
        ldap_packets = [pkt for pkt in packets if TCP in pkt and (pkt[TCP].sport == 389 or pkt[TCP].dport == 389)]

        if len(ldap_packets) >= 3:
            # First packet should be SYN
            syn = ldap_packets[0]
            assert syn[TCP].flags.S == 1
            assert syn[TCP].dport == 389

    def test_ldap_bind_in_traffic(self):
        """Test LDAP traffic includes bind operations."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Find LDAP data packets with bind requests
        ldap_data = [pkt for pkt in packets if TCP in pkt and Raw in pkt and b"CORP\\" in bytes(pkt[Raw])]

        # Should have some LDAP bind requests
        assert len(ldap_data) > 0

    def test_ldap_search_in_traffic(self):
        """Test LDAP traffic includes search operations."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Find LDAP data packets with search requests
        ldap_data = [pkt for pkt in packets if TCP in pkt and Raw in pkt and b"objectClass" in bytes(pkt[Raw])]

        # Should have some LDAP search requests
        assert len(ldap_data) > 0


# =============================================================================
# RDP Tests
# =============================================================================


class TestRDP:
    """Test RDP (Remote Desktop Protocol) session generation."""

    def test_rdp_application_data_generation(self):
        """Test RDP application data generation."""
        size = 100
        data = generate_rdp_application_data(size)

        # Verify it's bytes
        assert isinstance(data, bytes)

        # Verify approximate size (should be close to requested)
        assert 90 <= len(data) <= 110

    def test_rdp_application_data_sizes(self):
        """Test RDP application data with various sizes."""
        sizes = [50, 100, 500, 1000]

        for size in sizes:
            data = generate_rdp_application_data(size)
            # Allow 10% tolerance
            assert int(size * 0.9) <= len(data) <= int(size * 1.1)

    def test_rdp_session_tcp_handshake(self):
        """Test RDP session starts with TCP handshake."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 50000
        start_time = 1234567890.0
        duration = 10

        packets = generate_rdp_session(src_ip, dst_ip, sport, start_time, duration)

        # Should have packets
        assert len(packets) > 0

        # First packet should be SYN to port 3389
        syn = packets[0]
        assert TCP in syn
        assert syn[TCP].flags.S == 1
        assert syn[TCP].dport == 3389

    def test_rdp_session_data_exchange(self):
        """Test RDP session includes bidirectional data exchange."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 50000
        start_time = 1234567890.0
        duration = 10

        packets = generate_rdp_session(src_ip, dst_ip, sport, start_time, duration)

        # Find PSH-ACK packets (data transfer)
        data_packets = [pkt for pkt in packets if TCP in pkt and pkt[TCP].flags.P == 1]

        # Should have multiple data exchanges
        assert len(data_packets) > 0

        # Should have traffic in both directions
        client_to_server = [pkt for pkt in data_packets if pkt[IP].src == src_ip]
        server_to_client = [pkt for pkt in data_packets if pkt[IP].src == dst_ip]

        assert len(client_to_server) > 0
        assert len(server_to_client) > 0

    def test_rdp_session_duration(self):
        """Test RDP session respects duration parameter."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 50000
        start_time = 1234567890.0
        duration = 20

        packets = generate_rdp_session(src_ip, dst_ip, sport, start_time, duration)

        # Last packet should be within duration window
        last_time = max(pkt.time for pkt in packets)
        assert last_time <= start_time + duration + 1.0  # Allow 1s tolerance

    def test_rdp_traffic_generation(self):
        """Test RDP traffic generation with serializer."""
        start_time = 1234567890.0
        duration = 30

        packets = generate_rdp_traffic(start_time, duration, serializer=None)

        # Should generate multiple RDP sessions
        assert len(packets) > 0

        # Find RDP packets (port 3389)
        rdp_packets = [pkt for pkt in packets if TCP in pkt and (pkt[TCP].sport == 3389 or pkt[TCP].dport == 3389)]

        assert len(rdp_packets) > 0

    def test_rdp_traffic_multiple_sessions(self):
        """Test RDP traffic creates multiple independent sessions."""
        start_time = 1234567890.0
        duration = 60

        packets = generate_rdp_traffic(start_time, duration, serializer=None)

        # Find SYN packets (new sessions)
        syn_packets = [pkt for pkt in packets if TCP in pkt and pkt[TCP].flags.S == 1 and pkt[TCP].dport == 3389]

        # Should have 2-3 sessions (as per implementation)
        assert 2 <= len(syn_packets) <= 3

    def test_rdp_session_window_growth(self):
        """Test RDP session implements TCP window growth."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 50000
        start_time = 1234567890.0
        duration = 30

        packets = generate_rdp_session(src_ip, dst_ip, sport, start_time, duration)

        # Find server-to-client packets
        server_packets = [pkt for pkt in packets if TCP in pkt and pkt[IP].src == dst_ip and pkt[TCP].sport == 3389]

        if len(server_packets) > 50:
            # Check window sizes increase over time
            early_windows = [pkt[TCP].window for pkt in server_packets[:25] if hasattr(pkt[TCP], "window")]
            late_windows = [pkt[TCP].window for pkt in server_packets[-25:] if hasattr(pkt[TCP], "window")]

            if early_windows and late_windows:
                avg_early = sum(early_windows) / len(early_windows)
                avg_late = sum(late_windows) / len(late_windows)

                # Window should grow or stay the same
                assert avg_late >= avg_early

    def test_rdp_with_serializer(self):
        """Test RDP traffic generation with serializer."""
        start_time = 1234567890.0
        duration = 30

        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=True) as tmp:
            serializer = FastPacketSerializer(tmp.name)

            # Generate traffic directly to serializer
            packets = generate_rdp_traffic(start_time, duration, serializer=serializer)

            # Should return empty list when using serializer
            assert packets == []

            # Close serializer
            serializer.close()

            # Verify file was created and has content
            import os

            assert os.path.exists(tmp.name)
            assert os.path.getsize(tmp.name) > 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestAuthenticationIntegration:
    """Integration tests for combined authentication protocols."""

    def test_kerberos_ldap_traffic_mix(self):
        """Test Kerberos and LDAP traffic are both generated."""
        start_time = 1234567890.0
        duration = 120

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Find Kerberos packets (UDP port 88)
        kerberos_packets = [pkt for pkt in packets if UDP in pkt and (pkt[UDP].sport == 88 or pkt[UDP].dport == 88)]

        # Find LDAP packets (TCP port 389)
        ldap_packets = [pkt for pkt in packets if TCP in pkt and (pkt[TCP].sport == 389 or pkt[TCP].dport == 389)]

        # Should have both types of traffic
        assert len(kerberos_packets) > 0
        assert len(ldap_packets) > 0

    def test_kerberos_ldap_auth_count(self):
        """Test Kerberos/LDAP generates expected number of authentications."""
        start_time = 1234567890.0
        duration = 100

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Target is ~0.2 auths per second
        # duration = 100 -> target_auths = 100 * 0.2 = 20
        expected_auths = int(duration * 0.2)

        # Count authentication sessions (Kerberos pairs or LDAP handshakes)
        kerberos_reqs = len([pkt for pkt in packets if UDP in pkt and pkt[UDP].dport == 88])
        ldap_syns = len([pkt for pkt in packets if TCP in pkt and pkt[TCP].flags.S == 1 and pkt[TCP].dport == 389])

        total_auths = kerberos_reqs + ldap_syns

        # Should be close to expected (allow 50% tolerance)
        assert total_auths >= expected_auths * 0.5
        assert total_auths <= expected_auths * 1.5

    def test_rdp_realistic_timing(self):
        """Test RDP sessions have realistic timing between exchanges."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 50000
        start_time = 1234567890.0
        duration = 20

        packets = generate_rdp_session(src_ip, dst_ip, sport, start_time, duration)

        # Find data packets
        data_packets = [pkt for pkt in packets if TCP in pkt and Raw in pkt]

        if len(data_packets) > 2:
            # Check delays between consecutive packets
            delays = []
            for i in range(1, len(data_packets)):
                delay = data_packets[i].time - data_packets[i - 1].time
                delays.append(delay)

            # Most delays should be in realistic range (0.001 to 2 seconds)
            realistic_delays = [d for d in delays if 0.001 <= d <= 2.0]
            assert len(realistic_delays) >= len(delays) * 0.8  # 80% should be realistic

    def test_all_auth_protocols_packets_valid(self):
        """Test all authentication protocol packets are valid Scapy packets."""
        start_time = 1234567890.0
        duration = 60

        # Test Kerberos/LDAP
        kerberos_ldap_packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)
        for pkt in kerberos_ldap_packets:
            assert Ether in pkt
            assert IP in pkt or hasattr(pkt, "src")
            assert hasattr(pkt, "time")

        # Test RDP
        rdp_packets = generate_rdp_traffic(start_time, duration, serializer=None)
        for pkt in rdp_packets:
            assert Ether in pkt
            assert IP in pkt
            assert TCP in pkt
            assert hasattr(pkt, "time")

    def test_auth_protocols_with_serializer(self):
        """Test all authentication protocols work with serializer."""
        start_time = 1234567890.0
        duration = 30

        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=True) as tmp:
            serializer = FastPacketSerializer(tmp.name)

            # Generate all auth traffic
            kerberos_ldap_packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=serializer)
            rdp_packets = generate_rdp_traffic(start_time, duration, serializer=serializer)

            # Should return empty lists when using serializer
            assert kerberos_ldap_packets == []
            assert rdp_packets == []

            # Close
            serializer.close()

            # Verify file exists and has content
            import os

            assert os.path.exists(tmp.name)
            assert os.path.getsize(tmp.name) > 0


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestAuthenticationEdgeCases:
    """Test edge cases and error handling in authentication protocols."""

    def test_kerberos_zero_duration(self):
        """Test Kerberos traffic with zero duration."""
        start_time = 1234567890.0
        duration = 0

        packets = generate_kerberos_ldap_traffic(start_time, duration, serializer=None)

        # Should produce no packets or minimal packets
        assert isinstance(packets, list)

    def test_rdp_short_duration(self):
        """Test RDP session with very short duration."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 50000
        start_time = 1234567890.0
        duration = 1  # 1 second

        packets = generate_rdp_session(src_ip, dst_ip, sport, start_time, duration)

        # Should still have handshake at minimum
        assert len(packets) >= 3  # SYN, SYN-ACK, ACK

    def test_ldap_special_characters_in_filter(self):
        """Test LDAP search with special characters in filter."""
        base_dn = "DC=corp,DC=local"
        filter_str = "(cn=test*user)"

        search_req = generate_ldap_search_request(base_dn, filter_str)

        # Should handle special characters
        assert isinstance(search_req, bytes)
        assert filter_str.encode() in search_req

    def test_rdp_application_data_zero_size(self):
        """Test RDP application data with zero size."""
        data = generate_rdp_application_data(0)

        # Should return empty or minimal data
        assert isinstance(data, bytes)
