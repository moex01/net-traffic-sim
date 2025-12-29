"""Tests for NTP protocol simulation."""

from __future__ import annotations

import time
from io import BytesIO

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from net_traffic_sim.protocols.ntp import (
    NTP_PORT,
    NTP_VERSION,
    STRATUM_PRIMARY,
    STRATUM_SECONDARY,
    generate_ntp_background_polling,
    generate_ntp_pool_queries,
    generate_ntp_query,
    generate_ntp_response,
)
from net_traffic_sim.serializer import FastPacketSerializer


class TestNTPQuery:
    """Test NTP client query generation."""

    def test_generate_ntp_query_basic(self):
        """Test basic NTP client query."""
        client_ip = "10.1.1.100"
        ntp_server = "129.6.15.28"
        start_time = time.time()

        packets = generate_ntp_query(client_ip, ntp_server, start_time)

        # Should have only request
        assert len(packets) == 1, "Should have only NTP query packet"

        # Verify packet structure
        query = packets[0]
        assert IP in query
        assert UDP in query
        assert query[IP].src == client_ip
        assert query[IP].dst == ntp_server
        assert query[UDP].dport == NTP_PORT

        # Verify NTP packet
        assert Raw in query
        ntp_payload = query[Raw].load
        assert len(ntp_payload) == 48, "NTP packet should be exactly 48 bytes"

        # Verify NTP version and mode (client mode = 3)
        li_vn_mode = ntp_payload[0]
        version = (li_vn_mode >> 3) & 0x07
        mode = li_vn_mode & 0x07
        assert version == NTP_VERSION, f"Should be NTPv{NTP_VERSION}"
        assert mode == 3, "Client mode should be 3"

    def test_ntp_query_with_serializer(self):
        """Test NTP query with serializer."""
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=10) as serializer:
            packets = generate_ntp_query("10.1.1.100", "129.6.15.28", time.time(), serializer=serializer)

            assert len(packets) == 0, "Should return empty list with serializer"
            assert serializer.packet_count == 1, "Serializer should have 1 packet"


class TestNTPResponse:
    """Test NTP query/response exchange."""

    def test_generate_ntp_response_basic(self):
        """Test basic NTP query/response exchange."""
        client_ip = "10.1.1.100"
        ntp_server = "129.6.15.28"
        start_time = time.time()

        packets = generate_ntp_response(client_ip, ntp_server, start_time)

        # Should have request + response
        assert len(packets) == 2, "Should have NTP query and response"

        # Verify query packet
        query = packets[0]
        assert IP in query
        assert query[IP].src == client_ip
        assert query[IP].dst == ntp_server
        assert query[UDP].dport == NTP_PORT

        query_payload = query[Raw].load
        assert len(query_payload) == 48
        query_mode = query_payload[0] & 0x07
        assert query_mode == 3, "Query should be client mode (3)"

        # Verify response packet
        response = packets[1]
        assert IP in response
        assert response[IP].src == ntp_server
        assert response[IP].dst == client_ip
        assert response[UDP].sport == NTP_PORT

        response_payload = response[Raw].load
        assert len(response_payload) == 48
        response_mode = response_payload[0] & 0x07
        assert response_mode == 4, "Response should be server mode (4)"

    def test_ntp_response_stratum_levels(self):
        """Test NTP response with different stratum levels."""
        client_ip = "10.1.1.100"
        ntp_server = "129.6.15.28"
        start_time = time.time()

        # Test stratum 1 (primary reference)
        packets = generate_ntp_response(client_ip, ntp_server, start_time, stratum=STRATUM_PRIMARY)
        assert len(packets) == 2
        stratum = packets[1][Raw].load[1]
        assert stratum == STRATUM_PRIMARY

        # Test stratum 2 (secondary reference)
        packets = generate_ntp_response(client_ip, ntp_server, start_time, stratum=STRATUM_SECONDARY)
        assert len(packets) == 2
        stratum = packets[1][Raw].load[1]
        assert stratum == STRATUM_SECONDARY

    def test_ntp_response_with_serializer(self):
        """Test NTP response with serializer."""
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=10) as serializer:
            packets = generate_ntp_response("10.1.1.100", "129.6.15.28", time.time(), serializer=serializer)

            assert len(packets) == 0, "Should return empty list with serializer"
            assert serializer.packet_count == 2, "Serializer should have 2 packets"


class TestNTPBackgroundPolling:
    """Test NTP background polling traffic."""

    def test_generate_ntp_background_polling_basic(self):
        """Test basic NTP background polling."""
        client_ip = "10.1.1.100"
        ntp_server = "129.6.15.28"
        start_time = time.time()
        duration = 200  # 200 seconds

        packets = generate_ntp_background_polling(client_ip, ntp_server, start_time, duration)

        # Should have at least 1 poll (request + response)
        assert len(packets) >= 2, "Should have at least one NTP poll exchange"

        # All requests should be from client to server
        requests = [p for p in packets if p[IP].src == client_ip]
        responses = [p for p in packets if p[IP].src == ntp_server]

        assert len(requests) == len(responses), "Should have equal requests and responses"

        # Verify all are NTP packets
        for pkt in packets:
            assert UDP in pkt
            assert pkt[UDP].dport == NTP_PORT or pkt[UDP].sport == NTP_PORT

    def test_ntp_background_polling_duration(self):
        """Test NTP polling respects duration."""
        client_ip = "10.1.1.100"
        ntp_server = "129.6.15.28"
        start_time = 1000.0
        duration = 300  # 5 minutes

        packets = generate_ntp_background_polling(client_ip, ntp_server, start_time, duration)

        # Get timestamps from all packets
        if packets:
            first_time = packets[0].time
            last_time = packets[-1].time

            assert first_time >= start_time, "First packet should be at or after start_time"
            assert last_time <= start_time + duration + 10, "Last packet should be within duration (+10s tolerance)"

    def test_ntp_background_polling_with_serializer(self):
        """Test NTP background polling with serializer."""
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=100) as serializer:
            packets = generate_ntp_background_polling("10.1.1.100", "129.6.15.28", time.time(), duration=200, serializer=serializer)

            assert len(packets) == 0, "Should return empty list with serializer"
            assert serializer.packet_count >= 2, "Serializer should have multiple packets"


class TestNTPPoolQueries:
    """Test NTP pool.ntp.org style queries."""

    def test_generate_ntp_pool_queries_default_servers(self):
        """Test NTP pool queries with default servers."""
        client_ip = "10.1.1.100"
        start_time = time.time()

        packets = generate_ntp_pool_queries(client_ip, start_time=start_time)

        # Should have 4 servers × 2 packets (query + response) = 8 packets
        assert len(packets) == 8, "Should have 8 packets (4 servers × 2)"

        # Verify all packets are from/to client
        for pkt in packets:
            assert IP in pkt
            assert client_ip in [pkt[IP].src, pkt[IP].dst]

    def test_generate_ntp_pool_queries_custom_servers(self):
        """Test NTP pool queries with custom servers."""
        client_ip = "10.1.1.100"
        custom_servers = ["192.168.1.1", "192.168.1.2"]
        start_time = time.time()

        packets = generate_ntp_pool_queries(client_ip, pool_servers=custom_servers, start_time=start_time)

        # Should have 2 servers × 2 packets = 4 packets
        assert len(packets) == 4, "Should have 4 packets (2 servers × 2)"

        # Verify servers are queried
        server_ips = {pkt[IP].dst for pkt in packets if pkt[IP].src == client_ip}
        assert server_ips == set(custom_servers), "Should query all custom servers"

    def test_ntp_pool_queries_with_serializer(self):
        """Test NTP pool queries with serializer."""
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=20) as serializer:
            packets = generate_ntp_pool_queries("10.1.1.100", start_time=time.time(), serializer=serializer)

            assert len(packets) == 0, "Should return empty list with serializer"
            assert serializer.packet_count == 8, "Serializer should have 8 packets (4 servers × 2)"


class TestNTPPacketStructure:
    """Test NTP packet structure and format."""

    def test_ntp_packet_size(self):
        """Test all NTP packets are exactly 48 bytes."""
        packets = generate_ntp_response("10.1.1.100", "129.6.15.28", time.time())

        for pkt in packets:
            ntp_payload = pkt[Raw].load
            assert len(ntp_payload) == 48, "NTP packets must be exactly 48 bytes"

    def test_ntp_version_field(self):
        """Test NTP version field is correct."""
        packets = generate_ntp_query("10.1.1.100", "129.6.15.28", time.time())

        ntp_payload = packets[0][Raw].load
        li_vn_mode = ntp_payload[0]
        version = (li_vn_mode >> 3) & 0x07

        assert version == NTP_VERSION, f"NTP version should be {NTP_VERSION}"

    def test_ntp_mode_fields(self):
        """Test NTP mode fields are correct for client/server."""
        packets = generate_ntp_response("10.1.1.100", "129.6.15.28", time.time())

        # Client request should have mode 3
        client_payload = packets[0][Raw].load
        client_mode = client_payload[0] & 0x07
        assert client_mode == 3, "Client mode should be 3"

        # Server response should have mode 4
        server_payload = packets[1][Raw].load
        server_mode = server_payload[0] & 0x07
        assert server_mode == 4, "Server mode should be 4"
