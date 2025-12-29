"""Comprehensive tests for HTTP and HTTPS protocol generators."""

import time

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from net_traffic_sim.config import Config
from net_traffic_sim.protocols.http import (
    generate_http_file_download,
    generate_http_portal_traffic,
    generate_http_request_custom,
    generate_http_response,
    generate_http_response_body,
    generate_http_session,
    generate_http_sharepoint_traffic,
    generate_legitimate_toolpane_requests,
    generate_legitimate_vulnerable_endpoint_requests,
    generate_sharepoint_webpart_configuration_traffic,
)
from net_traffic_sim.protocols.https import (
    generate_https_external_traffic,
    generate_https_session,
    generate_tls_application_data,
    generate_tls_client_hello,
    generate_tls_server_hello,
)
from net_traffic_sim.state import GeneratorContext


@pytest.fixture
def test_context():
    """Fixture to provide a deterministic GeneratorContext."""
    config = Config.from_defaults().with_overrides(seed=42)
    ctx = GeneratorContext(config, seed=42)
    return ctx


class TestHTTPRequestGeneration:
    """Test HTTP request generation functions."""

    def test_generate_http_request_custom_get(self, test_context):
        """Test HTTP GET request generation with custom parameters."""
        request = generate_http_request_custom(
            method="GET",
            uri="/test/path",
            host="example.com",
            src_ip="192.168.1.10",
        )

        assert isinstance(request, bytes)
        assert b"GET /test/path HTTP/1.1" in request
        assert b"Host: example.com" in request
        assert b"User-Agent:" in request

    def test_generate_http_request_custom_post_with_body(self, test_context):
        """Test HTTP POST request with body."""
        body = b'{"key": "value"}'
        request = generate_http_request_custom(
            method="POST",
            uri="/api/endpoint",
            host="api.example.com",
            src_ip="192.168.1.10",
            body=body,
            is_api_call=True,
        )

        assert isinstance(request, bytes)
        assert b"POST /api/endpoint HTTP/1.1" in request
        assert b"Content-Length:" in request
        assert body in request

    @pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE"])
    def test_http_methods(self, test_context, method):
        """Test various HTTP methods."""
        request = generate_http_request_custom(
            method=method,
            uri="/resource",
            host="test.com",
            src_ip="192.168.1.10",
        )

        assert isinstance(request, bytes)
        assert method.encode() in request

    def test_http_request_with_referer(self, test_context):
        """Test HTTP request includes referer header."""
        request = generate_http_request_custom(
            method="GET",
            uri="/page2",
            host="example.com",
            src_ip="192.168.1.10",
            referer="https://example.com/page1",
        )

        assert b"Referer: https://example.com/page1" in request

    def test_http_request_close_connection(self, test_context):
        """Test HTTP request with Connection: close header."""
        request = generate_http_request_custom(
            method="GET",
            uri="/",
            host="example.com",
            src_ip="192.168.1.10",
            close_connection=True,
        )

        assert b"Connection: close" in request


class TestHTTPResponseGeneration:
    """Test HTTP response generation functions."""

    def test_generate_http_response_200(self, test_context):
        """Test HTTP 200 OK response generation."""
        response = generate_http_response(
            status_code=200,
            content_length=1024,
            src_ip="192.168.1.20",
            uri="/index.html",
            timestamp=time.time(),
        )

        assert isinstance(response, bytes)
        assert b"HTTP/1.1 200 OK" in response
        assert b"Content-Type:" in response
        assert b"Server:" in response

    @pytest.mark.parametrize("status_code", [200, 301, 302, 304, 404, 500])
    def test_http_response_status_codes(self, test_context, status_code):
        """Test various HTTP status codes."""
        response = generate_http_response(
            status_code=status_code,
            content_length=512,
            src_ip="192.168.1.20",
            uri="/test",
            timestamp=time.time(),
        )

        assert isinstance(response, bytes)
        assert f"HTTP/1.1 {status_code}".encode() in response

    def test_generate_http_response_body_html(self, test_context):
        """Test HTML response body generation."""
        body = generate_http_response_body(status_code=200, endpoint="/", content_type="text/html")

        assert isinstance(body, bytes)
        assert b"<html>" in body or b"<!DOCTYPE" in body

    def test_generate_http_response_body_json(self, test_context):
        """Test JSON response body generation."""
        body = generate_http_response_body(status_code=200, endpoint="/api/data", content_type="application/json")

        assert isinstance(body, bytes)
        # JSON responses should contain braces or brackets
        assert b"{" in body or b"[" in body


class TestHTTPTrafficGeneration:
    """Test full HTTP traffic generation with TCP handshakes."""

    def test_generate_http_portal_traffic(self, test_context):
        """Test HTTP portal traffic generation."""
        start_time = time.time()
        duration = 5.0

        packets = generate_http_portal_traffic(start_time, duration)

        assert isinstance(packets, list)
        if len(packets) > 0:
            # Verify packet structure
            for pkt in packets[:10]:  # Check first 10 packets
                assert Ether in pkt
                assert IP in pkt
                assert TCP in pkt

            # Check for HTTP payload in at least some packets
            has_http = any(pkt.haslayer(Raw) and (b"GET" in bytes(pkt[Raw]) or b"HTTP/1.1" in bytes(pkt[Raw])) for pkt in packets)
            assert has_http, "Expected at least one HTTP packet"

    def test_generate_http_session(self, test_context):
        """Test HTTP session generation with multiple requests."""
        start_time = time.time()
        packets = generate_http_session(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            start_time=start_time,
            num_requests=3,
        )

        assert isinstance(packets, list)
        assert len(packets) > 0

        # Should have TCP handshake (SYN, SYN-ACK, ACK)
        syn_packets = [pkt for pkt in packets if pkt.haslayer(TCP) and pkt[TCP].flags.S]
        assert len(syn_packets) > 0

    def test_generate_http_file_download(self, test_context):
        """Test HTTP file download traffic generation."""
        start_time = time.time()
        packets = generate_http_file_download(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            sport=50000,
            filename="document.pdf",
            filesize=1024 * 100,  # 100 KB
            start_time=start_time,
        )

        assert isinstance(packets, list)
        assert len(packets) > 0

        # Verify we have GET request
        has_get = any(pkt.haslayer(Raw) and b"GET" in bytes(pkt[Raw]) and b"document.pdf" in bytes(pkt[Raw]) for pkt in packets)
        assert has_get, "Expected GET request for document.pdf"

    def test_generate_http_sharepoint_traffic(self, test_context):
        """Test SharePoint-specific HTTP traffic generation."""
        start_time = time.time()
        duration = 5.0

        packets = generate_http_sharepoint_traffic(start_time, duration)

        assert isinstance(packets, list)
        # SharePoint traffic should generate packets
        assert len(packets) > 0


class TestHTTPSharePointEndpoints:
    """Test SharePoint-specific HTTP endpoint generators."""

    def test_generate_legitimate_toolpane_requests(self, test_context):
        """Test SharePoint toolpane request generation."""
        start_time = time.time()
        packets = generate_legitimate_toolpane_requests(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            sport=50000,
            start_time=start_time,
        )

        assert isinstance(packets, list)
        assert len(packets) > 0

    def test_generate_legitimate_vulnerable_endpoint_requests(self, test_context):
        """Test SharePoint vulnerable endpoint request generation."""
        start_time = time.time()
        packets = generate_legitimate_vulnerable_endpoint_requests(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            sport=50000,
            start_time=start_time,
        )

        assert isinstance(packets, list)
        assert len(packets) > 0

    def test_generate_sharepoint_webpart_configuration_traffic(self, test_context):
        """Test SharePoint webpart configuration traffic."""
        start_time = time.time()
        packets = generate_sharepoint_webpart_configuration_traffic(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            sport=50000,
            start_time=start_time,
        )

        assert isinstance(packets, list)
        assert len(packets) > 0


class TestTLSHandshake:
    """Test TLS/SSL handshake generation for HTTPS."""

    def test_generate_tls_client_hello(self, test_context):
        """Test TLS Client Hello generation."""
        timestamp = time.time()
        client_hello = generate_tls_client_hello(sni="example.com", timestamp=timestamp)

        assert isinstance(client_hello, bytes)
        assert len(client_hello) > 0
        # TLS record starts with 0x16 (Handshake)
        assert client_hello[0] == 0x16
        # Should contain SNI
        assert b"example.com" in client_hello

    def test_generate_tls_server_hello(self, test_context):
        """Test TLS Server Hello generation."""
        timestamp = time.time()
        server_hello = generate_tls_server_hello(timestamp=timestamp)

        assert isinstance(server_hello, bytes)
        assert len(server_hello) > 0


class TestHTTPSTrafficGeneration:
    """Test full HTTPS traffic generation with TLS."""

    def test_generate_https_session(self, test_context):
        """Test HTTPS session generation."""
        start_time = time.time()

        packets = generate_https_session(
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",  # External IP
            sport=50000,
            sni="example.com",
            start_time=start_time,
        )

        assert isinstance(packets, list)
        if len(packets) > 0:
            # Verify packet structure
            for pkt in packets[:10]:
                assert Ether in pkt
                assert IP in pkt
                assert TCP in pkt

            # Check for TLS handshake (0x16 = Handshake content type)
            has_tls = any(pkt.haslayer(Raw) and bytes(pkt[Raw])[0:1] == b"\x16" for pkt in packets if pkt.haslayer(Raw))
            assert has_tls, "Expected at least one TLS handshake packet"

    def test_generate_https_external_traffic(self, test_context):
        """Test HTTPS external browsing traffic."""
        start_time = time.time()
        duration = 5.0

        packets = generate_https_external_traffic(start_time, duration)

        assert isinstance(packets, list)
        # Should generate some HTTPS traffic
        assert len(packets) > 0

        # Verify TCP handshakes for HTTPS (port 443)
        https_packets = [pkt for pkt in packets if pkt.haslayer(TCP) and (pkt[TCP].sport == 443 or pkt[TCP].dport == 443)]
        assert len(https_packets) > 0

    def test_generate_tls_application_data(self, test_context):
        """Test TLS application data generation."""
        app_data = generate_tls_application_data(size=1024)

        assert isinstance(app_data, bytes)
        assert len(app_data) > 0


class TestHTTPHeaderValidation:
    """Test HTTP header generation and validation."""

    def test_http_headers_include_user_agent(self, test_context):
        """Test that HTTP requests include User-Agent header."""
        request = generate_http_request_custom(method="GET", uri="/", host="example.com", src_ip="192.168.1.10")

        assert b"User-Agent:" in request

    def test_http_headers_include_host(self, test_context):
        """Test that HTTP requests include Host header."""
        request = generate_http_request_custom(method="GET", uri="/", host="example.com", src_ip="192.168.1.10")

        assert b"Host: example.com" in request

    def test_http_response_includes_server_header(self, test_context):
        """Test that HTTP responses include Server header."""
        response = generate_http_response(
            status_code=200,
            content_length=1024,
            src_ip="192.168.1.20",
            uri="/",
            timestamp=time.time(),
        )

        assert b"Server:" in response

    def test_http_response_includes_content_type(self, test_context):
        """Test that HTTP responses include Content-Type header."""
        response = generate_http_response(
            status_code=200,
            content_length=1024,
            src_ip="192.168.1.20",
            uri="/index.html",
            timestamp=time.time(),
        )

        assert b"Content-Type:" in response


class TestHTTPErrorHandling:
    """Test HTTP error handling and edge cases."""

    def test_http_404_response(self, test_context):
        """Test HTTP 404 Not Found response."""
        response = generate_http_response(
            status_code=404,
            content_length=256,
            src_ip="192.168.1.20",
            uri="/nonexistent",
            timestamp=time.time(),
        )

        assert b"HTTP/1.1 404" in response

    def test_http_500_response(self, test_context):
        """Test HTTP 500 Internal Server Error response."""
        response = generate_http_response(
            status_code=500,
            content_length=256,
            src_ip="192.168.1.20",
            uri="/error",
            timestamp=time.time(),
        )

        assert b"HTTP/1.1 500" in response

    def test_http_redirect_responses(self, test_context):
        """Test HTTP redirect responses (301, 302)."""
        for status_code in [301, 302]:
            response = generate_http_response(
                status_code=status_code,
                content_length=0,
                src_ip="192.168.1.20",
                uri="/old-path",
                timestamp=time.time(),
            )

            assert f"HTTP/1.1 {status_code}".encode() in response
