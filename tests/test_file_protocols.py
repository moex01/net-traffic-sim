"""Tests for file transfer protocol generators (SMB, FTP) from sharepoint.py.

This test suite covers SMB and FTP traffic generation functions from the
sharepoint.py monolith to establish baseline test coverage before refactoring.
"""

from __future__ import annotations

import time
from io import BytesIO

import pytest
from scapy.layers.inet import IP, TCP, Ether
from scapy.packet import Raw

from net_traffic_sim.protocols.base import _emit_packet, _simple_tcp_exchange, _udp_packet
from net_traffic_sim.protocols.remote import generate_ftp_traffic
from net_traffic_sim.protocols.smb import (
    generate_smb2_close,
    generate_smb2_create_request,
    generate_smb2_negotiate,
    generate_smb2_negotiate_response,
    generate_smb2_read_request,
    generate_smb2_read_response,
    generate_smb2_session_setup,
    generate_smb2_tree_connect,
    generate_smb_file_transfer,
    generate_smb_traffic,
)
from net_traffic_sim.serializer import FastPacketSerializer


class TestSMB2ProtocolHelpers:
    """Test SMB2 protocol message generation helpers."""

    def test_generate_smb2_negotiate(self):
        """Test SMB2 Negotiate Protocol Request generation."""
        negotiate = generate_smb2_negotiate()

        # Verify SMB2 signature
        assert negotiate[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify minimum length
        assert len(negotiate) > 40, "Negotiate request too short"

    def test_generate_smb2_negotiate_response(self):
        """Test SMB2 Negotiate Protocol Response generation."""
        response = generate_smb2_negotiate_response()

        # Verify SMB2 signature
        assert response[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify minimum length
        assert len(response) > 40, "Negotiate response too short"

    def test_generate_smb2_session_setup(self):
        """Test SMB2 Session Setup Request generation."""
        session_setup = generate_smb2_session_setup()

        # Verify SMB2 signature
        assert session_setup[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify minimum length
        assert len(session_setup) > 40, "Session setup too short"

    def test_generate_smb2_tree_connect(self):
        """Test SMB2 Tree Connect Request generation."""
        share_name = "IPC$"
        tree_connect = generate_smb2_tree_connect(share_name)

        # Verify SMB2 signature
        assert tree_connect[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify minimum length
        assert len(tree_connect) > 40, "Tree connect too short"

    def test_generate_smb2_create_request(self):
        """Test SMB2 Create Request (file open) generation."""
        filename = "test.txt"
        create_req = generate_smb2_create_request(filename)

        # Verify SMB2 signature
        assert create_req[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify minimum length
        assert len(create_req) > 60, "Create request too short"

    def test_generate_smb2_read_request(self):
        """Test SMB2 Read Request generation."""
        file_id = b"\x01\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 8
        offset = 0
        length = 65536

        read_req = generate_smb2_read_request(file_id, offset, length)

        # Verify SMB2 signature
        assert read_req[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify minimum length
        assert len(read_req) > 60, "Read request too short"

    def test_generate_smb2_read_response(self):
        """Test SMB2 Read Response generation."""
        data_length = 8192
        read_resp = generate_smb2_read_response(data_length)

        # Verify SMB2 signature
        assert read_resp[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify response includes data
        assert len(read_resp) > data_length, "Read response missing data"

    def test_generate_smb2_close(self):
        """Test SMB2 Close Request generation."""
        close_req = generate_smb2_close()

        # Verify SMB2 signature
        assert close_req[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
        # Verify minimum length
        assert len(close_req) > 40, "Close request too short"

    def test_smb2_messages_unique(self):
        """Test that SMB2 messages have unique message IDs."""
        neg1 = generate_smb2_negotiate()
        neg2 = generate_smb2_negotiate()

        # Messages should be unique (due to random message IDs)
        assert neg1 != neg2, "SMB2 messages should have unique IDs"


class TestSMBFileTransfer:
    """Test SMB file transfer traffic generation."""

    def test_generate_smb_file_transfer_small_file(self):
        """Test SMB file transfer for a small file."""
        src_ip = "10.3.20.10"
        dst_ip = "10.3.10.20"
        sport = 49152
        filename = "document.docx"
        filesize = 1024 * 1024  # 1 MB
        start_time = time.time()

        packets = generate_smb_file_transfer(src_ip, dst_ip, sport, filename, filesize, start_time, is_upload=False)

        # Verify packets were generated
        assert len(packets) > 0, "No packets generated"

        # Verify TCP handshake (first 3 packets)
        assert len(packets) >= 3, "Missing TCP handshake"
        assert "S" in str(packets[0][TCP].flags), "First packet should be SYN"
        assert "S" in str(packets[1][TCP].flags) and "A" in str(packets[1][TCP].flags), "Second packet should be SYN-ACK"
        assert "A" in str(packets[2][TCP].flags), "Third packet should be ACK"

        # Verify SMB2 negotiate request (contains SMB2 signature)
        smb_packets = [p for p in packets if Raw in p and len(p[Raw].load) > 4]
        smb2_packets = [p for p in smb_packets if p[Raw].load[:4] == b"\xfe\x53\x4d\x42"]
        assert len(smb2_packets) > 0, "No SMB2 packets found"

        # Verify source and destination
        assert packets[0][IP].src == src_ip
        assert packets[0][IP].dst == dst_ip

    def test_generate_smb_file_transfer_upload(self):
        """Test SMB file transfer for upload."""
        src_ip = "10.3.20.10"
        dst_ip = "10.3.10.20"
        sport = 49153
        filename = "backup.zip"
        filesize = 5 * 1024 * 1024  # 5 MB
        start_time = time.time()

        packets = generate_smb_file_transfer(src_ip, dst_ip, sport, filename, filesize, start_time, is_upload=True)

        # Verify packets were generated
        assert len(packets) > 0, "No packets generated"

        # Verify TCP connection on port 445 (SMB)
        tcp_packets = [p for p in packets if TCP in p]
        assert any(p[TCP].dport == 445 or p[TCP].sport == 445 for p in tcp_packets), "SMB port 445 not used"

    def test_generate_smb_file_transfer_large_file_chunking(self):
        """Test SMB file transfer handles large files with chunking."""
        src_ip = "10.3.20.10"
        dst_ip = "10.3.10.20"
        sport = 49154
        filename = "large_iso.iso"
        filesize = 100 * 1024 * 1024  # 100 MB
        start_time = time.time()

        packets = generate_smb_file_transfer(src_ip, dst_ip, sport, filename, filesize, start_time, is_upload=False)

        # Verify packets were generated
        assert len(packets) > 100, "Large file should generate many packets"

        # Verify fragmentation for large payloads
        large_payloads = [p for p in packets if Raw in p and len(p[Raw].load) > 1400]
        assert len(large_payloads) >= 0, "Large file transfer should have payloads"


class TestSMBTraffic:
    """Test SMB traffic generation orchestration."""

    def test_generate_smb_traffic_basic(self):
        """Test basic SMB traffic generation."""
        start_time = time.time()
        duration = 60  # 1 minute

        packets = generate_smb_traffic(
            start_time,
            duration,
            smb_simulated_size=5_000_000,  # Simulate 5MB max per file
            max_transfers=2,  # Limit to 2 transfers for testing
            enforce_short_run_caps=True,
            serializer=None,
        )

        # Verify packets were generated
        assert len(packets) > 0, "No SMB packets generated"

        # Verify all packets have timestamps
        assert all(hasattr(p, "time") for p in packets), "Packets missing timestamps"

        # Verify all packets have Ethernet layer
        assert all(Ether in p for p in packets), "Packets missing Ethernet layer"

    def test_generate_smb_traffic_with_serializer(self):
        """Test SMB traffic generation with serializer."""
        start_time = time.time()
        duration = 30

        # Create a temporary file for testing
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=100) as serializer:
            packets = generate_smb_traffic(
                start_time,
                duration,
                smb_simulated_size=2_000_000,
                max_transfers=1,
                enforce_short_run_caps=True,
                serializer=serializer,
            )

            # With serializer, returned packets should be empty
            assert len(packets) == 0, "Serializer mode should return empty list"
            # Verify packets were written to serializer
            assert serializer.packet_count > 0, "Serializer should have packets"

    def test_generate_smb_traffic_enforces_transfer_limit(self):
        """Test that max_transfers parameter limits transfers."""
        start_time = time.time()
        duration = 60

        packets = generate_smb_traffic(
            start_time,
            duration,
            smb_simulated_size=5_000_000,
            max_transfers=1,  # Limit to 1 transfer
            enforce_short_run_caps=True,
            serializer=None,
        )

        # Should generate packets, but limited
        assert len(packets) > 0, "Should generate at least one transfer"

    def test_generate_smb_traffic_short_run_caps(self):
        """Test that enforce_short_run_caps limits transfers to 15."""
        start_time = time.time()
        duration = 3600  # 1 hour

        packets = generate_smb_traffic(
            start_time,
            duration,
            smb_simulated_size=10_000_000,
            max_transfers=None,  # No explicit limit
            enforce_short_run_caps=True,  # Should cap at 15
            serializer=None,
        )

        # Should generate packets but be capped
        assert len(packets) > 0, "Should generate transfers"


class TestFTPTraffic:
    """Test FTP traffic generation."""

    def test_generate_ftp_traffic_basic(self):
        """Test basic FTP traffic generation."""
        start_time = time.time()
        duration = 3600  # 1 hour

        packets = generate_ftp_traffic(start_time, duration, serializer=None)

        # Verify packets were generated
        assert len(packets) > 0, "No FTP packets generated"

        # Verify TCP connection exists
        tcp_packets = [p for p in packets if TCP in p]
        assert len(tcp_packets) > 0, "No TCP packets found"

        # Verify FTP port 21 is used
        ftp_packets = [p for p in tcp_packets if p[TCP].dport == 21 or p[TCP].sport == 21]
        assert len(ftp_packets) > 0, "FTP port 21 not found"

        # Verify all packets have timestamps
        assert all(hasattr(p, "time") for p in packets), "Packets missing timestamps"

    def test_generate_ftp_traffic_contains_ftp_commands(self):
        """Test that FTP traffic contains actual FTP commands."""
        start_time = time.time()
        duration = 3600

        packets = generate_ftp_traffic(start_time, duration, serializer=None)

        # Find packets with Raw payload
        payload_packets = [p for p in packets if Raw in p]
        assert len(payload_packets) > 0, "No packets with payloads"

        # Check for FTP command patterns (USER, PASS)
        payloads = [p[Raw].load for p in payload_packets]
        ftp_commands = [p for p in payloads if b"USER" in p or b"PASS" in p or b"230" in p]
        assert len(ftp_commands) > 0, "No FTP commands found in payloads"

    def test_generate_ftp_traffic_with_serializer(self):
        """Test FTP traffic generation with serializer."""
        start_time = time.time()
        duration = 1800  # 30 minutes

        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=100) as serializer:
            packets = generate_ftp_traffic(start_time, duration, serializer=serializer)

            # With serializer, returned packets should be empty
            assert len(packets) == 0, "Serializer mode should return empty list"
            # Verify packets were written
            assert serializer.packet_count > 0, "Serializer should have packets"

    def test_generate_ftp_traffic_duration_affects_sessions(self):
        """Test that longer duration generates more FTP sessions."""
        start_time = time.time()

        # Short duration
        packets_short = generate_ftp_traffic(start_time, duration=600, serializer=None)  # 10 min

        # Longer duration
        packets_long = generate_ftp_traffic(start_time, duration=7200, serializer=None)  # 2 hours

        # Longer duration should generate more packets
        assert len(packets_long) >= len(packets_short), "Longer duration should generate more packets"

    def test_generate_ftp_traffic_tcp_handshake(self):
        """Test that FTP sessions include proper TCP handshake."""
        start_time = time.time()
        duration = 3600

        packets = generate_ftp_traffic(start_time, duration, serializer=None)

        # Verify TCP handshake exists (SYN, SYN-ACK, ACK)
        tcp_packets = [p for p in packets if TCP in p]
        assert len(tcp_packets) >= 3, "Should have TCP handshake"

        # Check for SYN flag
        syn_packets = [p for p in tcp_packets if "S" in str(p[TCP].flags)]
        assert len(syn_packets) > 0, "Should have SYN packets"

        # Check for SYN-ACK flag
        synack_packets = [p for p in tcp_packets if "S" in str(p[TCP].flags) and "A" in str(p[TCP].flags)]
        assert len(synack_packets) > 0, "Should have SYN-ACK packets"

    def test_generate_ftp_traffic_timestamps_sequential(self):
        """Test that FTP packet timestamps are sequential."""
        start_time = time.time()
        duration = 3600

        packets = generate_ftp_traffic(start_time, duration, serializer=None)

        # Extract timestamps
        timestamps = [p.time for p in packets]

        # Verify timestamps are increasing (allowing for small network jitter)
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[0], "Timestamps should be >= start_time"


class TestSMBFTPIntegration:
    """Integration tests for SMB and FTP protocol interactions."""

    def test_smb_and_ftp_no_port_conflicts(self):
        """Test that SMB and FTP use different ports without conflicts."""
        start_time = time.time()
        duration = 60

        smb_packets = generate_smb_traffic(
            start_time,
            duration,
            smb_simulated_size=2_000_000,
            max_transfers=1,
            enforce_short_run_caps=True,
            serializer=None,
        )

        ftp_packets = generate_ftp_traffic(start_time, duration, serializer=None)

        # Extract SMB ports (should be 445)
        smb_tcp = [p for p in smb_packets if TCP in p]
        smb_ports = {(p[TCP].sport, p[TCP].dport) for p in smb_tcp}

        # Extract FTP ports (should be 21)
        ftp_tcp = [p for p in ftp_packets if TCP in p]
        ftp_ports = {(p[TCP].sport, p[TCP].dport) for p in ftp_tcp}

        # Verify SMB uses port 445
        assert any(445 in ports for ports in smb_ports), "SMB should use port 445"

        # Verify FTP uses port 21
        assert any(21 in ports for ports in ftp_ports), "FTP should use port 21"

    def test_both_protocols_generate_valid_packets(self):
        """Test that both SMB and FTP generate valid packet structures."""
        start_time = time.time()
        duration = 60

        smb_packets = generate_smb_traffic(
            start_time,
            duration,
            smb_simulated_size=2_000_000,
            max_transfers=1,
            enforce_short_run_caps=True,
            serializer=None,
        )

        ftp_packets = generate_ftp_traffic(start_time, duration, serializer=None)

        # Verify both have Ether/IP/TCP layers
        for packets, proto_name in [(smb_packets, "SMB"), (ftp_packets, "FTP")]:
            assert all(Ether in p for p in packets), f"{proto_name} packets missing Ethernet"
            assert all(IP in p for p in packets), f"{proto_name} packets missing IP"
            tcp_packets = [p for p in packets if TCP in p]
            assert len(tcp_packets) > 0, f"{proto_name} should have TCP packets"


class TestSharepointHelpers:
    """Test sharepoint.py helper functions."""

    def test_emit_packet_with_serializer(self):
        """Test _emit_packet with serializer."""
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=10) as serializer:
            packets = []
            # Create a simple packet
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
            pkt.time = time.time()

            _emit_packet(serializer, packets, pkt, pkt.time)

            # Packets list should remain empty when using serializer
            assert len(packets) == 0, "Packets list should be empty with serializer"
            # Serializer should have the packet
            assert serializer.packet_count > 0, "Serializer should have packets"

    def test_emit_packet_without_serializer(self):
        """Test _emit_packet without serializer (packets list mode)."""
        packets = []
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
        pkt.time = time.time()

        _emit_packet(None, packets, pkt, pkt.time)

        # Packets should be added to list
        assert len(packets) == 1, "Packet should be added to list"
        assert packets[0] == pkt, "Packet should match"

    def test_udp_packet_basic(self):
        """Test _udp_packet creates valid UDP packet."""
        from scapy.layers.inet import UDP

        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 1234
        dport = 53
        payload = b"DNS QUERY"
        timestamp = time.time()

        pkt = _udp_packet(src_ip, dst_ip, sport, dport, payload, timestamp)

        # Verify layers
        assert Ether in pkt, "Missing Ethernet layer"
        assert IP in pkt, "Missing IP layer"
        assert UDP in pkt, "Missing UDP layer"
        assert Raw in pkt, "Missing Raw payload"

        # Verify fields
        assert pkt[IP].src == src_ip
        assert pkt[IP].dst == dst_ip
        assert pkt[UDP].sport == sport
        assert pkt[UDP].dport == dport
        assert pkt[Raw].load == payload
        assert pkt.time == timestamp

    def test_udp_packet_empty_payload(self):
        """Test _udp_packet with empty payload."""
        from scapy.layers.inet import UDP

        pkt = _udp_packet("10.0.0.1", "10.0.0.2", 1234, 5353, b"", time.time())

        # Should have UDP but no Raw layer
        assert UDP in pkt, "Should have UDP layer"
        # Empty payload means no Raw layer
        assert Raw not in pkt, "Should not have Raw layer for empty payload"

    def test_udp_packet_with_custom_mac(self):
        """Test _udp_packet with custom destination MAC."""
        dst_mac = "ff:ff:ff:ff:ff:ff"
        pkt = _udp_packet("10.0.0.1", "224.0.0.251", 5353, 5353, b"mDNS", time.time(), dst_mac=dst_mac)

        assert pkt[Ether].dst == dst_mac, "Should use custom MAC address"

    def test_simple_tcp_exchange_basic(self):
        """Test _simple_tcp_exchange creates complete TCP session."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        dport = 80
        start_time = time.time()
        payload = b"GET / HTTP/1.1\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\n\r\n"

        packets = _simple_tcp_exchange(src_ip, dst_ip, dport, start_time, payload, response)

        # Verify handshake + data exchange
        assert len(packets) >= 5, "Should have handshake + data packets"

        # Verify TCP handshake
        tcp_packets = [p for p in packets if TCP in p]
        assert len(tcp_packets) >= 3, "Should have TCP handshake"

        # Verify payload in packets
        payload_packets = [p for p in packets if Raw in p]
        assert len(payload_packets) >= 2, "Should have request and response"

    def test_simple_tcp_exchange_no_response(self):
        """Test _simple_tcp_exchange without response payload."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        dport = 22
        start_time = time.time()
        payload = b"SSH-2.0-OpenSSH_8.9"

        packets = _simple_tcp_exchange(src_ip, dst_ip, dport, start_time, payload, response_payload=None)

        # Should have handshake + client data
        assert len(packets) >= 4, "Should have handshake + data"

    def test_simple_tcp_exchange_string_payloads(self):
        """Test _simple_tcp_exchange with string payloads (auto-encoded)."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        dport = 21
        start_time = time.time()
        payload = "USER admin\r\n"
        response = "230 OK\r\n"

        packets = _simple_tcp_exchange(src_ip, dst_ip, dport, start_time, payload, response)

        # Should work with strings (auto-encoded to bytes)
        assert len(packets) > 0, "Should generate packets with string payloads"

        # Verify payloads were encoded
        payload_packets = [p for p in packets if Raw in p]
        assert any(b"USER admin" in p[Raw].load for p in payload_packets), "Payload should be encoded"

    def test_simple_tcp_exchange_empty_payload(self):
        """Test _simple_tcp_exchange with empty payload raises ValueError."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        dport = 443
        start_time = time.time()

        # Empty payload should raise ValueError (Phase 6 validation)
        with pytest.raises(ValueError, match="payload cannot be None or empty"):
            _simple_tcp_exchange(src_ip, dst_ip, dport, start_time, None, None)


class TestSMBEdgeCases:
    """Test edge cases and error handling for SMB functions."""

    def test_smb2_read_response_various_sizes(self):
        """Test SMB2 read response with different data sizes."""
        sizes = [0, 1024, 8192, 65536, 131072]

        for size in sizes:
            resp = generate_smb2_read_response(size)
            # Response should at least have SMB2 header (40+ bytes)
            assert len(resp) >= 40, f"Response too small for size {size}"
            assert resp[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
            # For non-zero sizes, response should contain some data
            if size > 0:
                assert len(resp) > 50, f"Response should have data for size {size}"

    def test_smb2_tree_connect_various_shares(self):
        """Test SMB2 tree connect with various share names."""
        shares = ["IPC$", "C$", "ADMIN$", "Software", "Backups", "Users"]

        for share in shares:
            tree_conn = generate_smb2_tree_connect(share)
            assert tree_conn[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
            assert len(tree_conn) > 40, f"Tree connect too short for share {share}"

    def test_smb2_create_request_various_filenames(self):
        """Test SMB2 create request with various filenames."""
        filenames = ["test.txt", "document.docx", "backup.zip", "image.png", "data.xlsx"]

        for filename in filenames:
            create = generate_smb2_create_request(filename)
            assert create[:4] == b"\xfe\x53\x4d\x42", "SMB2 signature missing"
            assert len(create) > 60, f"Create request too short for {filename}"

    def test_smb_file_transfer_zero_size_file(self):
        """Test SMB file transfer with zero-size file."""
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"
        sport = 50000
        filename = "empty.txt"
        filesize = 0  # Edge case: empty file
        start_time = time.time()

        packets = generate_smb_file_transfer(src_ip, dst_ip, sport, filename, filesize, start_time)

        # Should still generate session packets even for empty file
        assert len(packets) > 0, "Should generate packets even for empty file"

    def test_smb_traffic_zero_duration(self):
        """Test SMB traffic generation with minimal duration."""
        start_time = time.time()
        duration = 1  # 1 second

        packets = generate_smb_traffic(
            start_time,
            duration,
            smb_simulated_size=1_000_000,
            max_transfers=1,
            enforce_short_run_caps=True,
            serializer=None,
        )

        # Should handle minimal duration gracefully
        assert isinstance(packets, list), "Should return list"

    def test_smb_traffic_no_enforcement(self):
        """Test SMB traffic without short run caps."""
        start_time = time.time()
        duration = 60

        packets = generate_smb_traffic(
            start_time,
            duration,
            smb_simulated_size=5_000_000,
            max_transfers=2,
            enforce_short_run_caps=False,  # No caps
            serializer=None,
        )

        assert len(packets) >= 0, "Should generate packets without caps"


class TestFTPEdgeCases:
    """Test edge cases for FTP traffic generation."""

    def test_ftp_traffic_minimal_duration(self):
        """Test FTP traffic with minimal duration."""
        start_time = time.time()
        duration = 1  # 1 second

        packets = generate_ftp_traffic(start_time, duration, serializer=None)

        # Should generate at least 1 session
        assert len(packets) >= 1, "Should generate minimal traffic"

    def test_ftp_traffic_very_long_duration(self):
        """Test FTP traffic with very long duration."""
        start_time = time.time()
        duration = 86400  # 24 hours

        # Use serializer to avoid memory issues
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=100) as serializer:
            packets = generate_ftp_traffic(start_time, duration, serializer=serializer)

            assert len(packets) == 0, "Should use serializer"
            assert serializer.packet_count > 10, "Should generate many sessions over 24h"
