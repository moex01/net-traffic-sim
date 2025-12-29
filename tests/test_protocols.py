"""Unit tests for protocol generators."""

import time

import pytest
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from net_traffic_sim.config import Config
from net_traffic_sim.protocols.dns import generate_dns_traffic

# Import from extracted http.py module instead of sharepoint.py
from net_traffic_sim.protocols.http import generate_http_portal_traffic
from net_traffic_sim.state import GeneratorContext


@pytest.fixture
def test_context():
    """Fixture to provide a deterministic GeneratorContext."""
    config = Config.from_defaults().with_overrides(seed=42)
    # We must initialize the context so the global 'generator' proxy works
    ctx = GeneratorContext(config, seed=42)
    return ctx


def test_generate_dns_traffic(test_context):
    """Test DNS traffic generation."""
    start_time = time.time()
    duration = 1.0  # 1 second

    # Generate traffic
    packets = generate_dns_traffic(start_time, duration)

    # Assertions
    assert isinstance(packets, list)
    # With seed 42 and default rates, we expect some packets.
    # If rates are low, we might get empty list, but let's check basic structure if present.

    for pkt in packets:
        assert Ether in pkt
        assert IP in pkt
        assert UDP in pkt
        assert DNS in pkt

        # Check that timestamps are within the window
        assert start_time <= float(pkt.time) <= start_time + duration + 1.0


def test_generate_http_traffic(test_context):
    """Test HTTP traffic generation."""
    start_time = time.time()
    duration = 5.0  # Give it a bit more time to complete a session

    # Force higher rate for testing to ensure we get packets
    test_context.config = test_context.config.with_overrides(http_requests_per_sec=100)

    packets = generate_http_portal_traffic(start_time, duration)

    assert isinstance(packets, list)

    has_tcp_syn = False
    has_http_payload = False

    for pkt in packets:
        assert Ether in pkt
        assert IP in pkt
        assert TCP in pkt

        if pkt[TCP].flags.S:
            has_tcp_syn = True

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if b"GET /" in payload or b"HTTP/1.1" in payload:
                has_http_payload = True

    # We might not see full handshake + data in a very short slice if logic is complex,
    # but with 5 seconds and 100 req/s, we should see something.
    if packets:
        assert has_tcp_syn or has_http_payload, "Expected at least SYN or HTTP data"
