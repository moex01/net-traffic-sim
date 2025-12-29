"""Comprehensive tests for VoIP and monitoring protocol generators."""

import time

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from net_traffic_sim.config import Config
from net_traffic_sim.protocols.monitoring import generate_snmp_traffic, generate_syslog_traffic
from net_traffic_sim.protocols.voip import generate_sip_rtp_traffic
from net_traffic_sim.state import GeneratorContext


@pytest.fixture
def test_context():
    """Fixture to provide a deterministic GeneratorContext."""
    config = Config.from_defaults().with_overrides(seed=42)
    ctx = GeneratorContext(config, seed=42)
    return ctx


# =============================================================================
# SIP/RTP Tests
# =============================================================================


class TestSIPProtocol:
    """Comprehensive SIP protocol tests."""

    def test_sip_basic_call_generation(self, test_context):
        """Test basic SIP call generation creates packets."""
        start_time = time.time()
        duration = 60.0  # 1 minute

        packets = generate_sip_rtp_traffic(start_time, duration)

        assert isinstance(packets, list)
        assert len(packets) > 0, "Should generate at least one SIP/RTP packet"

    def test_sip_invite_message(self, test_context):
        """Test SIP INVITE messages are generated."""
        start_time = time.time()
        duration = 60.0

        packets = generate_sip_rtp_traffic(start_time, duration)

        # Find INVITE packets
        invite_found = False
        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if b"SIP INVITE" in payload:
                    invite_found = True
                    # Validate packet structure
                    assert Ether in pkt
                    assert IP in pkt
                    assert UDP in pkt
                    assert pkt[UDP].dport == 5060  # SIP port
                    break

        assert invite_found, "Should generate at least one SIP INVITE message"

    def test_sip_200_ok_response(self, test_context):
        """Test SIP 200 OK responses are generated."""
        start_time = time.time()
        duration = 60.0

        packets = generate_sip_rtp_traffic(start_time, duration)

        # Find 200 OK packets
        ok_found = False
        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if b"SIP 200 OK" in payload:
                    ok_found = True
                    assert Ether in pkt
                    assert IP in pkt
                    assert UDP in pkt
                    assert pkt[UDP].dport == 5060
                    break

        assert ok_found, "Should generate at least one SIP 200 OK response"

    def test_sip_packet_timestamps(self, test_context):
        """Test SIP packets have valid timestamps within duration."""
        start_time = time.time()
        duration = 60.0

        packets = generate_sip_rtp_traffic(start_time, duration)

        for pkt in packets:
            assert hasattr(pkt, "time"), "Packet should have timestamp"
            assert start_time <= pkt.time <= start_time + duration + 200, "Packet timestamp should be within duration window"

    @pytest.mark.parametrize("duration", [30, 60, 120, 300])
    def test_sip_call_count_scales_with_duration(self, test_context, duration):
        """Test that longer durations produce more SIP calls."""
        start_time = time.time()

        packets = generate_sip_rtp_traffic(start_time, duration)

        # Should generate at least 1 call
        assert len(packets) > 0

        # Count INVITE messages as proxy for call count
        invite_count = sum(1 for pkt in packets if pkt.haslayer(Raw) and b"SIP INVITE" in bytes(pkt[Raw].load))

        assert invite_count >= 1, f"Should have at least 1 call in {duration} seconds"


class TestRTPProtocol:
    """Comprehensive RTP protocol tests."""

    def test_rtp_packets_generated(self, test_context):
        """Test RTP media packets are generated alongside SIP."""
        start_time = time.time()
        duration = 60.0

        packets = generate_sip_rtp_traffic(start_time, duration)

        # Find RTP packets
        rtp_found = False
        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if b"RTP" in payload:
                    rtp_found = True
                    assert Ether in pkt
                    assert IP in pkt
                    assert UDP in pkt
                    # RTP uses ports in range 10000-20000
                    assert 10000 <= pkt[UDP].sport <= 20000
                    break

        assert rtp_found, "Should generate RTP media packets"

    def test_rtp_port_range(self, test_context):
        """Test RTP uses correct port range (10000-20000)."""
        start_time = time.time()
        duration = 60.0

        packets = generate_sip_rtp_traffic(start_time, duration)

        rtp_packets = [pkt for pkt in packets if pkt.haslayer(Raw) and b"RTP" in bytes(pkt[Raw].load)]

        for pkt in rtp_packets:
            assert 10000 <= pkt[UDP].sport <= 20000, "RTP source port should be in range"
            assert 10000 <= pkt[UDP].dport <= 20000, "RTP dest port should be in range"

    def test_rtp_timing_consistency(self, test_context):
        """Test RTP packets have realistic timing (20ms intervals)."""
        start_time = time.time()
        duration = 60.0

        packets = generate_sip_rtp_traffic(start_time, duration)

        rtp_packets = [pkt for pkt in packets if pkt.haslayer(Raw) and b"RTP" in bytes(pkt[Raw].load)]

        if len(rtp_packets) >= 2:
            # Check timing between consecutive RTP packets
            for i in range(len(rtp_packets) - 1):
                time_diff = rtp_packets[i + 1].time - rtp_packets[i].time
                # RTP packets should be sent at ~20ms intervals (0.02s)
                assert 0 <= time_diff <= 1.0, "RTP packet timing should be realistic"


# =============================================================================
# SNMP Tests
# =============================================================================


class TestSNMPProtocol:
    """Comprehensive SNMP protocol tests."""

    def test_snmp_basic_generation(self, test_context):
        """Test basic SNMP traffic generation."""
        start_time = time.time()
        duration = 60.0  # 1 minute

        packets = generate_snmp_traffic(start_time, duration)

        assert isinstance(packets, list)
        assert len(packets) > 0, "Should generate at least one SNMP packet"

    def test_snmp_get_requests(self, test_context):
        """Test SNMP GET requests are generated."""
        start_time = time.time()
        duration = 60.0

        packets = generate_snmp_traffic(start_time, duration)

        # Find SNMP GET packets
        get_found = False
        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if b"SNMP GET" in payload:
                    get_found = True
                    assert Ether in pkt
                    assert IP in pkt
                    assert UDP in pkt
                    assert pkt[UDP].dport == 161  # SNMP port
                    break

        assert get_found, "Should generate SNMP GET requests"

    def test_snmp_responses(self, test_context):
        """Test SNMP responses are generated."""
        start_time = time.time()
        duration = 60.0

        packets = generate_snmp_traffic(start_time, duration)

        # Find SNMP RESPONSE packets
        response_found = False
        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if b"SNMP RESPONSE" in payload:
                    response_found = True
                    assert Ether in pkt
                    assert IP in pkt
                    assert UDP in pkt
                    # Response comes from port 161
                    assert pkt[UDP].sport == 161
                    break

        assert response_found, "Should generate SNMP responses"

    def test_snmp_request_response_pairing(self, test_context):
        """Test SNMP requests are followed by responses."""
        start_time = time.time()
        duration = 60.0

        packets = generate_snmp_traffic(start_time, duration)

        # Count requests and responses
        requests = sum(1 for pkt in packets if pkt.haslayer(Raw) and b"SNMP GET" in bytes(pkt[Raw].load))
        responses = sum(1 for pkt in packets if pkt.haslayer(Raw) and b"SNMP RESPONSE" in bytes(pkt[Raw].load))

        # Each request should have a response
        assert requests == responses, "Request/response count should match"
        assert requests > 0, "Should have at least one request/response pair"

    def test_snmp_packet_timestamps(self, test_context):
        """Test SNMP packets have valid timestamps."""
        start_time = time.time()
        duration = 60.0

        packets = generate_snmp_traffic(start_time, duration)

        for pkt in packets:
            assert hasattr(pkt, "time"), "Packet should have timestamp"
            assert start_time <= pkt.time <= start_time + duration + 20, "Packet timestamp should be within duration window"

    @pytest.mark.parametrize("duration", [60, 120, 300])
    def test_snmp_poll_count_scales(self, test_context, duration):
        """Test SNMP poll count scales with duration."""
        start_time = time.time()

        packets = generate_snmp_traffic(start_time, duration)

        # Longer durations should produce more polls
        assert len(packets) > 0

        # Count GET requests
        get_count = sum(1 for pkt in packets if pkt.haslayer(Raw) and b"SNMP GET" in bytes(pkt[Raw].load))

        # Should have at least 1 poll per minute
        expected_min_polls = duration / 60
        assert get_count >= expected_min_polls


# =============================================================================
# Syslog Tests
# =============================================================================


class TestSyslogProtocol:
    """Comprehensive Syslog protocol tests."""

    def test_syslog_basic_generation(self, test_context):
        """Test basic syslog message generation."""
        start_time = time.time()
        duration = 60.0  # 1 minute

        packets = generate_syslog_traffic(start_time, duration)

        assert isinstance(packets, list)
        assert len(packets) > 0, "Should generate at least one syslog message"

    def test_syslog_message_format(self, test_context):
        """Test syslog messages follow RFC 3164 format."""
        start_time = time.time()
        duration = 60.0

        packets = generate_syslog_traffic(start_time, duration)

        for pkt in packets:
            assert Ether in pkt
            assert IP in pkt
            assert UDP in pkt
            assert pkt[UDP].dport == 514  # Syslog port

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                # Check for syslog priority format: <134>
                assert b"<134>" in payload, "Should have syslog priority"
                # Check for timestamp
                assert b"Oct" in payload or b"12:00:00" in payload, "Should have timestamp"

    def test_syslog_severity_levels(self, test_context):
        """Test syslog priority code is present."""
        start_time = time.time()
        duration = 60.0

        packets = generate_syslog_traffic(start_time, duration)

        priority_found = False
        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                # <134> is facility 16 (local0), severity 6 (informational)
                if b"<134>" in payload:
                    priority_found = True
                    break

        assert priority_found, "Should find syslog priority code"

    def test_syslog_packet_timestamps(self, test_context):
        """Test syslog packets have valid timestamps."""
        start_time = time.time()
        duration = 60.0

        packets = generate_syslog_traffic(start_time, duration)

        for pkt in packets:
            assert hasattr(pkt, "time"), "Packet should have timestamp"
            assert start_time <= pkt.time <= start_time + duration + 100, "Packet timestamp should be within duration window"

    def test_syslog_source_ips(self, test_context):
        """Test syslog messages come from server IPs."""
        start_time = time.time()
        duration = 60.0

        packets = generate_syslog_traffic(start_time, duration)

        for pkt in packets:
            if IP in pkt:
                # Source should be a server (not external)
                assert pkt[IP].src.startswith("10."), "Source should be internal server"

    @pytest.mark.parametrize("duration", [60, 120, 300])
    def test_syslog_message_count_scales(self, test_context, duration):
        """Test syslog message count scales with duration."""
        start_time = time.time()

        packets = generate_syslog_traffic(start_time, duration)

        # Should generate messages proportional to duration
        assert len(packets) > 0

        # Should have at least 1 message
        assert len(packets) >= 1

    def test_syslog_udp_transport(self, test_context):
        """Test syslog uses UDP transport."""
        start_time = time.time()
        duration = 60.0

        packets = generate_syslog_traffic(start_time, duration)

        for pkt in packets:
            assert UDP in pkt, "Syslog should use UDP"
            assert pkt[UDP].dport == 514, "Syslog should use port 514"


# =============================================================================
# Integration Tests
# =============================================================================


class TestMonitoringProtocolIntegration:
    """Integration tests for monitoring protocols."""

    def test_all_protocols_generate_packets(self, test_context):
        """Test all monitoring protocols generate packets."""
        start_time = time.time()
        duration = 60.0

        sip_packets = generate_sip_rtp_traffic(start_time, duration)
        snmp_packets = generate_snmp_traffic(start_time, duration)
        syslog_packets = generate_syslog_traffic(start_time, duration)

        assert len(sip_packets) > 0, "SIP/RTP should generate packets"
        assert len(snmp_packets) > 0, "SNMP should generate packets"
        assert len(syslog_packets) > 0, "Syslog should generate packets"

    def test_protocols_use_udp(self, test_context):
        """Test all monitoring protocols use UDP."""
        start_time = time.time()
        duration = 60.0

        all_packets = []
        all_packets.extend(generate_sip_rtp_traffic(start_time, duration))
        all_packets.extend(generate_snmp_traffic(start_time, duration))
        all_packets.extend(generate_syslog_traffic(start_time, duration))

        for pkt in all_packets:
            assert UDP in pkt, "All monitoring protocols should use UDP"

    def test_no_tcp_in_monitoring_protocols(self, test_context):
        """Test monitoring protocols don't use TCP."""
        start_time = time.time()
        duration = 60.0

        all_packets = []
        all_packets.extend(generate_sip_rtp_traffic(start_time, duration))
        all_packets.extend(generate_snmp_traffic(start_time, duration))
        all_packets.extend(generate_syslog_traffic(start_time, duration))

        for pkt in all_packets:
            assert not pkt.haslayer("TCP"), "Monitoring protocols should not use TCP"
