"""HTTP protocol traffic generators."""

from __future__ import annotations

import json
import random
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer


from ..config import (
    ADMIN_WORKSTATION_IPS,
    FILE_TRANSFERS,
    RETRANSMISSION_RATE_OTHER,
    SHAREPOINT_HOSTNAME,
    SHAREPOINT_SERVER_IP,
    USER_WORKSTATION_IPS,
    Config,
)
from ..helpers import (
    build_realistic_http_headers,
    format_guid_for_url,
    format_http_date,
    generate_correlation_id,
    generate_etag,
    generate_random_guid,
    generate_request_digest,
    generate_request_duration,
    generate_sharepoint_health_score,
    generate_sharepoint_json_response,
    generate_sharepoint_list_guid,
    generate_view_guid,
    get_sharepoint_endpoints,
    should_use_range_request,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import (
    apply_retransmissions_filtered,
    create_tcp_ack,
    create_tcp_psh_ack,
    exponential_delay,
    fragment_large_payload,
    get_time_of_day_multiplier,
    should_generate_packet,
    tcp_fin_handshake,
    tcp_handshake,
)

logger = get_logger(__name__)


def generate_http_request_custom(
    method,
    uri,
    host,
    src_ip,
    body=b"",
    referer=None,
    is_api_call=False,
    request_timestamp=None,
    close_connection=False,
):
    """Generate HTTP request with realistic headers and proper order"""

    # Get user agent for this source IP
    user_agent = generator.get_user_agent(src_ip)

    # Build headers with proper order
    has_body = len(body) > 0 if isinstance(body, bytes) else len(body.encode()) > 0
    body_length = len(body) if isinstance(body, bytes) else len(body.encode())

    headers = build_realistic_http_headers(
        method=method,
        uri=uri,
        host=host,
        user_agent=user_agent,
        src_ip=src_ip,
        has_body=has_body,
        body_length=body_length,
        referer=referer,
        is_api_call=is_api_call,
        request_timestamp=request_timestamp,
        close_connection=close_connection,
        session_cookie=generator.get_session_cookie(src_ip),
    )

    # Add body if present
    if has_body:
        if isinstance(body, bytes):
            return headers.encode() + body
        else:
            return headers.encode() + body.encode()

    return headers.encode()


def generate_http_response_body(status_code, endpoint, content_type="text/html"):
    """Generate realistic HTTP response bodies matching Content-Length"""

    if status_code == 200:
        if "api" in endpoint.lower():
            # JSON API response
            body = '{"result":"ok","data":[]}'
        elif endpoint.endswith(".aspx"):
            # SharePoint HTML response
            body = """<!DOCTYPE html>
<html><head><title>SharePoint</title></head>
<body><div id="contentBox">
<a href="/_layouts/15/start.aspx">Home</a>
</div></body></html>"""
        else:
            body = "<html><body>OK</body></html>"

    elif status_code == 302:
        # Redirect responses usually have minimal body
        body = ""

    elif status_code == 401:
        # Unauthorized - explains why
        body = "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head><body><h1>Unauthorized</h1></body></html>"

    elif status_code == 403:
        body = "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1></body></html>"

    elif status_code == 404:
        body = "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"

    else:
        body = ""

    return body.encode()


def generate_http_response(
    status_code,
    content_length,
    src_ip,
    uri,
    timestamp,
    cached_etag=None,
    cached_last_modified=None,
    should_return_304=None,
):
    """Generate HTTP response payload with caching support"""
    status_messages = {200: "OK", 302: "Found", 304: "Not Modified", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}

    # Check if should return 304
    if cached_etag is None and cached_last_modified is None and should_return_304 is None:
        should_return_304_response, etag, last_modified, _ = generator.should_return_304(src_ip, uri, timestamp)
    else:
        should_return_304_response = bool(should_return_304)
        etag = cached_etag or generate_etag()
        last_modified = cached_last_modified if cached_last_modified is not None else timestamp - random.uniform(3600, 86400)

    # Override status_code if cache hit
    if should_return_304_response and status_code == 200:
        status_code = 304
        content_length = 0  # 304 responses have no body

    # Get server versions
    iis_version, aspnet_version = generator.get_server_versions("10.3.10.11")  # SPSRV01

    response = f"HTTP/1.1 {status_code} {status_messages.get(status_code, 'OK')}\r\n"

    # Date header (always present)
    response += f"Date: {format_http_date(timestamp)}\r\n"

    response += f"Server: {iis_version}\r\n"

    # SharePoint correlation headers (appear on all SharePoint responses)
    if "/_api/" in uri or "/_layouts/" in uri or "/_vti_bin/" in uri:
        correlation_id = generate_correlation_id()
        response += f"SPRequestGuid: {correlation_id}\r\n"
        response += f"request-id: {correlation_id}\r\n"
        response += "SPRequestDuration: " + str(generate_request_duration()) + "\r\n"
        response += "MicrosoftSharePointTeamServices: 16.0.0." + str(random.randint(10000, 10500)) + "\r\n"

    if status_code == 304:
        # 304 responses include ETag and Last-Modified but NO Content-Length/Type
        response += f"ETag: {etag}\r\n"
        response += f"Last-Modified: {format_http_date(last_modified)}\r\n"
        response += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
        response += "Connection: keep-alive\r\n"
        response += "\r\n"
        return response.encode()

    # Normal 200/other responses
    if "/_api/" in uri or "/_vti_bin/" in uri:
        content_type = "application/json;odata=verbose"
    elif uri.endswith(".aspx") or "/_layouts" in uri:
        content_type = "text/html; charset=utf-8"
    else:
        content_type = "text/html; charset=utf-8"

    body = generate_http_response_body(status_code, uri, content_type=content_type)
    if content_length:
        body = body[:content_length]
    content_length = len(body)

    response += f"Content-Length: {content_length}\r\n"
    response += f"Content-Type: {content_type}\r\n"
    response += f"ETag: {etag}\r\n"
    response += f"Last-Modified: {format_http_date(last_modified)}\r\n"
    response += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
    response += "X-Powered-By: ASP.NET\r\n"
    response += "Connection: keep-alive\r\n"
    response += f"Cache-Control: max-age={random.randint(60, 3600)}\r\n"  # 1min-1hr
    response += "\r\n"
    if body:
        return response.encode() + body
    return response.encode()


def generate_http_file_download(src_ip, dst_ip, sport, filename, filesize, start_time):
    """
    Generate HTTP file download with optional byte-range request support.
    Small files: Single connection with HTTP 200
    Large files (>10MB): Multiple range requests with HTTP 206
    """
    packets = []
    current_time = start_time

    # Check if should use range requests
    use_ranges, num_ranges, range_size = should_use_range_request(filesize, filename)

    encoded_filename = filename.replace(" ", "%20")
    uri = f"/_layouts/15/download.aspx?SourceUrl=/Shared%20Documents/{encoded_filename}"
    user_agent = generator.get_user_agent(src_ip)

    # Determine MIME type
    ext = filename.split(".")[-1].lower()
    mime_types = {
        "exe": "application/x-msdownload",
        "msi": "application/x-msi",
        "dll": "application/x-msdownload",
        "cab": "application/vnd.ms-cab-compressed",
        "msp": "application/octet-stream",
        "zip": "application/zip",
        "rar": "application/x-rar-compressed",
        "pdf": "application/pdf",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
    }
    content_type = mime_types.get(ext, "application/octet-stream")

    # FILE MAGIC BYTES (makes files exportable and appear valid)
    def get_file_header(filename):
        """Return magic bytes for common file types"""
        ext = filename.split(".")[-1].lower()
        headers = {
            "exe": b"MZ\x90\x00\x03\x00\x00\x00",  # PE executable
            "dll": b"MZ\x90\x00\x03\x00\x00\x00",  # PE DLL
            "msi": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE/MSI
            "cab": b"MSCF\x00\x00\x00\x00",  # Cabinet file
            "msp": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # Windows Installer Patch
            "xlsx": b"PK\x03\x04\x14\x00\x06\x00",  # ZIP-based Office
            "docx": b"PK\x03\x04\x14\x00\x06\x00",
            "pptx": b"PK\x03\x04\x14\x00\x06\x00",
            "zip": b"PK\x03\x04",
            "rar": b"Rar!\x1a\x07\x00",
            "pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
            "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
            "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
        }
        return headers.get(ext, b"")

    file_header = get_file_header(filename)

    # Range request flow for large files.
    if use_ranges:
        bytes_downloaded = 0
        range_num = 0
        current_sport = sport

        while bytes_downloaded < filesize and range_num < num_ranges:
            range_start = bytes_downloaded
            range_end = min(range_start + range_size - 1, filesize - 1)
            actual_range_size = range_end - range_start + 1

            # TCP handshake
            packets.extend(tcp_handshake(src_ip, dst_ip, current_sport, 8080, current_time))
            current_time += random_pool.delay_handshake()

            conn = generator.get_connection(src_ip, dst_ip, current_sport, 8080)
            conn_server = generator.get_connection(dst_ip, src_ip, 8080, current_sport)

            # HTTP GET with Range header
            request_headers = f"GET {uri} HTTP/1.1\r\n"
            request_headers += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
            request_headers += f"User-Agent: {user_agent}\r\n"
            request_headers += "Accept: */*\r\n"
            request_headers += f"Range: bytes={range_start}-{range_end}\r\n"
            request_headers += "Accept-Encoding: identity\r\n"
            request_headers += f"Cookie: session_id={generator.get_session_cookie(src_ip)}\r\n"
            request_headers += f"Referer: http://{SHAREPOINT_HOSTNAME}:8080/_layouts/15/start.aspx\r\n"
            request_headers += "\r\n"
            request = request_headers.encode()

            pkt = create_tcp_psh_ack(src_ip, dst_ip, current_sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
            packets.append(pkt)
            conn.seq += len(request)
            current_time += exponential_delay(0.010, 0.050, 50)

            # HTTP 206 Partial Content response
            iis_version, aspnet_version = generator.get_server_versions(dst_ip)
            response_headers = "HTTP/1.1 206 Partial Content\r\n"
            response_headers += f"Date: {format_http_date(current_time)}\r\n"
            response_headers += f"Server: {iis_version}\r\n"
            response_headers += f"Content-Length: {actual_range_size}\r\n"
            response_headers += f"Content-Type: {content_type}\r\n"
            response_headers += f"Content-Range: bytes {range_start}-{range_end}/{filesize}\r\n"
            response_headers += "Accept-Ranges: bytes\r\n"
            response_headers += f'Content-Disposition: attachment; filename="{filename}"\r\n'
            response_headers += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
            response_headers += "X-Powered-By: ASP.NET\r\n"
            response_headers += "\r\n"
            response_headers_bytes = response_headers.encode()

            pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, current_sport, conn_server.seq, conn.seq, 65535, response_headers_bytes, current_time)
            packets.append(pkt)
            conn_server.seq += len(response_headers_bytes)
            current_time += exponential_delay(0.005, 0.015, 100)

            # Client ACK
            pkt = create_tcp_ack(src_ip, dst_ip, current_sport, 8080, conn.seq, conn_server.seq, 65535, current_time)
            packets.append(pkt)
            conn.ack = conn_server.seq
            current_time += exponential_delay(0.001, 0.005, 200)

            # Send range data with magic bytes on first chunk
            bytes_sent_in_range = 0
            chunk_size = 536
            first_chunk_in_range = range_start == 0  # Only first range gets magic bytes
            packet_count = 0

            while bytes_sent_in_range < actual_range_size:
                # TCP congestion window growth
                if bytes_sent_in_range < 65536:
                    chunk_size = min(chunk_size + random.randint(50, 200), 1460)
                else:
                    chunk_size = random.choice([1380, 1448, 1460])

                if random.random() < 0.15:
                    chunk_size = random.randint(200, 800)

                chunk = min(chunk_size, actual_range_size - bytes_sent_in_range)

                # Apply magic bytes to first chunk of first range
                if first_chunk_in_range and file_header:
                    chunk_data = file_header + b"\x00" * (chunk - len(file_header))
                    first_chunk_in_range = False
                else:
                    chunk_data = bytes([random.randint(0, 255) for _ in range(chunk)])

                pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, current_sport, conn_server.seq, conn.seq, 65535, chunk_data, current_time)

                # Fragment if needed
                if len(chunk_data) > 1460:
                    frag_packets = fragment_large_payload(pkt, mss=1460)
                    packets.extend(frag_packets)
                    conn_server.seq += chunk
                    current_time = float(frag_packets[-1].time) + exponential_delay(0.0001, 0.005, 500)
                else:
                    packets.append(pkt)
                    conn_server.seq += chunk
                    current_time += exponential_delay(0.0001, 0.005, 500)

                bytes_sent_in_range += chunk
                packet_count += 1

                # Client ACK every 10 packets
                if packet_count % 10 == 0:
                    pkt = create_tcp_ack(src_ip, dst_ip, current_sport, 8080, conn.seq, conn_server.seq, 65535, current_time)
                    packets.append(pkt)
                    conn.ack = conn_server.seq
                    current_time += exponential_delay(0.001, 0.003, 500)

                current_time += exponential_delay(0.0001, 0.001, 1000)

            # Final ACK for this range
            pkt = create_tcp_ack(src_ip, dst_ip, current_sport, 8080, conn.seq, conn_server.seq, 65535, current_time)
            packets.append(pkt)

            # Close connection for this range
            current_time += exponential_delay(0.01, 0.05, 50)
            packets.extend(tcp_fin_handshake(src_ip, dst_ip, current_sport, 8080, current_time))

            bytes_downloaded += actual_range_size
            range_num += 1

            # New port for next range
            current_sport = generator.allocate_port(src_ip)
            current_time += random.uniform(0.05, 0.2)

        return packets

    # Single request flow for small files.
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 8080, current_time))
    current_time += random_pool.delay_handshake()

    conn = generator.get_connection(src_ip, dst_ip, sport, 8080)
    conn_server = generator.get_connection(dst_ip, src_ip, 8080, sport)

    request = build_realistic_http_headers(
        method="GET",
        uri=uri,
        host=f"{dst_ip}:8080",
        user_agent=user_agent,
        src_ip=src_ip,
        has_body=False,
        body_length=0,
        referer=f"http://{dst_ip}:8080/_layouts/15/start.aspx",
        is_api_call=False,
        request_timestamp=current_time,
        close_connection=False,
        session_cookie=generator.get_session_cookie(src_ip),
    ).encode()

    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
    packets.append(pkt)
    conn.seq += len(request)
    current_time += exponential_delay(0.010, 0.050, 50)

    iis_version, aspnet_version = generator.get_server_versions(dst_ip)
    response_headers = "HTTP/1.1 200 OK\r\n"
    response_headers += f"Content-Length: {filesize}\r\n"
    response_headers += f"Content-Type: {content_type}\r\n"
    response_headers += f'Content-Disposition: attachment; filename="{filename}"\r\n'
    response_headers += f"Server: {iis_version}\r\n"
    response_headers += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
    response_headers += "X-Powered-By: ASP.NET\r\n"
    response_headers += "\r\n"
    response_headers_bytes = response_headers.encode()

    pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response_headers_bytes, current_time)
    packets.append(pkt)
    conn_server.seq += len(response_headers_bytes)
    current_time += exponential_delay(0.005, 0.015, 100)

    pkt = create_tcp_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn_server.seq, 65535, current_time)
    packets.append(pkt)
    conn.ack = conn_server.seq
    current_time += exponential_delay(0.001, 0.005, 200)

    bytes_sent = 0
    chunk_size = 536
    first_chunk = True
    packet_count = 0

    while bytes_sent < filesize:
        if bytes_sent < 65536:
            chunk_size = min(chunk_size + random.randint(50, 200), 1460)
        else:
            chunk_size = random.choice([1380, 1448, 1460])

        if random.random() < 0.15:
            chunk_size = random.randint(200, 800)

        chunk = min(chunk_size, filesize - bytes_sent)

        if first_chunk and file_header:
            chunk_data = file_header + b"\x00" * (chunk - len(file_header))
            first_chunk = False
        else:
            chunk_data = bytes([random.randint(0, 255) for _ in range(chunk)])

        pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, sport, conn_server.seq, conn.seq, 65535, chunk_data, current_time)

        if len(chunk_data) > 1460:
            frag_packets = fragment_large_payload(pkt, mss=1460)
            packets.extend(frag_packets)
            conn_server.seq += chunk
            current_time = float(frag_packets[-1].time) + exponential_delay(0.0001, 0.005, 500)
        else:
            packets.append(pkt)
            conn_server.seq += chunk
            current_time += exponential_delay(0.0001, 0.005, 500)

        bytes_sent += chunk
        packet_count += 1

        if packet_count % 10 == 0:
            pkt = create_tcp_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn_server.seq, 65535, current_time)
            packets.append(pkt)
            conn.ack = conn_server.seq
            current_time += exponential_delay(0.001, 0.003, 500)

        current_time += exponential_delay(0.0001, 0.001, 1000)

    pkt = create_tcp_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn_server.seq, 65535, current_time)
    packets.append(pkt)

    return packets


def generate_http_session(src_ip, dst_ip, start_time, num_requests):
    """
    Generate HTTP session with realistic connection reuse.
    Real browsers reuse TCP connections for multiple requests (HTTP keep-alive).
    """
    packets = []
    current_time = start_time

    user_agent = generator.get_user_agent(src_ip)

    for req_num in range(num_requests):
        # Get or reuse HTTP connection
        sport, is_new_conn, should_close = generator.get_http_connection(src_ip, dst_ip, 8080, current_time)

        # New connection - do TCP handshake
        if is_new_conn:
            packets.extend(tcp_handshake(src_ip, dst_ip, sport, 8080, current_time))
            current_time += random_pool.delay_handshake()

        # Get connection state
        conn = generator.get_connection(src_ip, dst_ip, sport, 8080)
        conn_server = generator.get_connection(dst_ip, src_ip, 8080, sport)

        # Generate request
        method, uri, body = random.choice(get_sharepoint_endpoints())
        is_api_call = method == "POST" or "/_api/" in uri

        if body is None:
            body = ""
        body_bytes = body.encode() if isinstance(body, str) else body
        should_return_304_response, etag, last_modified, is_cached = generator.should_return_304(
            src_ip,
            uri,
            current_time,
        )
        request_payload = build_realistic_http_headers(
            method=method,
            uri=uri,
            host=f"{SHAREPOINT_HOSTNAME}:8080",
            user_agent=user_agent,
            src_ip=src_ip,
            has_body=len(body_bytes) > 0,
            body_length=len(body_bytes),
            referer=None,
            is_api_call=is_api_call,
            request_timestamp=current_time,
            close_connection=should_close,
            session_cookie=generator.get_session_cookie(src_ip),
            cached_etag=etag if is_cached else None,
            cached_last_modified=last_modified if is_cached else None,
        ).encode()

        if body_bytes:
            request_payload += body_bytes

        # Send request
        pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn.ack, 65535, request_payload, current_time)
        packets.append(pkt)
        conn.seq += len(request_payload)
        current_time += exponential_delay(0.003, 0.015, 100)

        # Server ACK
        pkt = create_tcp_ack(dst_ip, src_ip, 8080, sport, conn_server.seq, conn.seq, 65535, current_time)
        packets.append(pkt)
        current_time += exponential_delay(0.005, 0.030, 50)

        # Server response
        status_code = random.choices(
            [200, 302, 401, 403, 404, 500],
            weights=[85, 8, 1, 1, 0.5, 0.5],
        )[0]
        content_length = random.randint(200, 5000) if status_code == 200 else random.randint(50, 500)

        response_payload = generate_http_response(
            status_code,
            content_length,
            src_ip,
            uri,
            current_time,
            cached_etag=etag if is_cached else None,
            cached_last_modified=last_modified if is_cached else None,
            should_return_304=should_return_304_response,
        )

        pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response_payload, current_time)
        packets.append(pkt)
        conn_server.seq += len(response_payload)
        conn.ack = conn_server.seq
        current_time += exponential_delay(0.002, 0.010, 150)

        # Client ACK
        pkt = create_tcp_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn.ack, 65535, current_time)
        packets.append(pkt)

        # Close connection if needed (Connection: close header)
        if should_close or req_num == num_requests - 1:
            current_time += exponential_delay(0.01, 0.05, 50)
            packets.extend(tcp_fin_handshake(src_ip, dst_ip, sport, 8080, current_time))
            current_time += exponential_delay(0.1, 2.0, 2)  # Think time before next session
        else:
            # Keep connection alive, short delay before next request
            current_time += exponential_delay(0.05, 0.5, 5)  # 50-500ms between requests on same connection

    return packets


def generate_legitimate_toolpane_requests(src_ip, dst_ip, sport, start_time):
    """Generate legitimate ToolPane.aspx requests to blend with exploit traffic"""
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 8080, current_time))
    current_time += random_pool.delay_handshake()

    conn = generator.get_connection(src_ip, dst_ip, sport, 8080)
    conn_server = generator.get_connection(dst_ip, src_ip, 8080, sport)

    # Legitimate ToolPane.aspx request with realistic parameters
    toolpane_uri = "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&PageView=Shared"

    # Realistic ToolPane POST body with legitimate control URIs
    legitimate_controls = [
        "/_controltemplates/15/ContentByQueryWebPart.ascx",
        "/_controltemplates/15/ContentBySearchWebPart.ascx",
        "/_controltemplates/15/XsltListViewWebPart.ascx",
        "/_controltemplates/15/SummaryLinksWebPart.ascx",
        "/_controltemplates/15/TableOfContentsWebPart.ascx",
        "/_controltemplates/15/ContentEditorWebPart.ascx",
    ]

    control_uri = random.choice(legitimate_controls)

    # Legitimate DWP (Web Part Definition) with realistic property names
    legitimate_dwp = """<%@ Register Tagprefix="WebPartPages" Namespace="Microsoft.SharePoint.WebPartPages" Assembly="Microsoft.SharePoint, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<WebPartPages:DataFormWebPart runat="server"
    IsIncluded="True"
    FrameType="None"
    NoDefaultStyle="TRUE"
    ViewFlag="8"
    Title="Document Library View"
    Description="Displays documents from the site"
    IsVisible="True"
    ChromeType="None"
    AllowMinimize="False"
    AllowRemove="True"
    ListName="{B3A5A6E2-9F4C-4D8E-A1B2-C3D4E5F6A7B8}"
    ListDisplayName="Shared Documents"
    ViewContentTypeId="0x"
    PageSize="30"
    UseSQLDataSourcePaging="True"
    DataSourceID="DocumentLibraryDataSource"
    FireInitialRow="True"
    AllowEdit="True"
    AllowDelete="False" />"""

    # URL encode the parameters
    encoded_uri = urllib.parse.quote(f"http://10.3.10.11{control_uri}", safe="")
    encoded_dwp = urllib.parse.quote(legitimate_dwp, safe="")

    post_body = f"MSOTlPn_Uri={encoded_uri}&MSOTlPn_DWP={encoded_dwp}&MSOWebPartPage_PostbackSource=&MSOTlPn_Button=OK"

    request_text = f"POST {toolpane_uri} HTTP/1.1\r\n"
    request_text += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
    request_text += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0\r\n"
    request_text += "Referer: /_layouts/15/editpage.aspx\r\n"
    request_text += "Content-Type: application/x-www-form-urlencoded\r\n"
    request_text += f"Content-Length: {len(post_body)}\r\n"
    request_text += f"Cookie: session_id={generator.get_session_cookie(src_ip)}\r\n"
    request_text += "\r\n"
    request_text += post_body

    request = request_text.encode()

    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
    packets.append(pkt)
    conn.seq += len(request)
    current_time += exponential_delay(0.010, 0.050, 50)

    iis_version, aspnet_version = generator.get_server_versions(dst_ip)

    # Note: Generate realistic variable-size XML response body
    response_body = (
        b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ToolPane_Response>'
    )
    response_body += b"<data>Pane configuration data for web part</data>" * random.randint(5, 15)
    response_body += b"</ToolPane_Response></soap:Body></soap:Envelope>"

    response_text = "HTTP/1.1 200 OK\r\n"
    response_text += "Content-Type: application/xml\r\n"  # XML response for web part configuration.
    response_text += f"Server: {iis_version}\r\n"
    response_text += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
    response_text += "X-Powered-By: ASP.NET\r\n"
    response_text += f"Content-Length: {len(response_body)}\r\n"  # Use actual length
    response_text += "\r\n"

    response = response_text.encode() + response_body  # Add body to response

    pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response, current_time)
    packets.append(pkt)

    return packets


def generate_legitimate_vulnerable_endpoint_requests(src_ip, dst_ip, sport, start_time):
    """Generate legitimate requests to historically vulnerable SharePoint endpoints"""
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 8080, current_time))
    current_time += random_pool.delay_handshake()

    conn = generator.get_connection(src_ip, dst_ip, sport, 8080)
    conn_server = generator.get_connection(dst_ip, src_ip, 8080, sport)

    # Generate dynamic GUIDs for this request
    list_guid = format_guid_for_url(generate_sharepoint_list_guid())
    view_guid = format_guid_for_url(generate_view_guid())
    item_id = random.randint(1, 500)
    dialog_type = random.choice(["EmailPicker", "UserPicker", "PeoplePicker"])

    vulnerable_endpoints = [
        # PickerDialogFrame.aspx (CVE-2020-0932)
        {"uri": f"/_layouts/15/PickerDialogFrame.aspx?DialogType={dialog_type}", "method": "GET", "body": "", "referer": "/_layouts/15/people.aspx"},
        # ViewEditForm.aspx (information disclosure)
        {"uri": f"/_layouts/15/ViewEditForm.aspx?List={list_guid}&ID={item_id}", "method": "GET", "body": "", "referer": "/_layouts/15/viewlsts.aspx"},
        # emailPickerDialog.aspx (CVE-2020-16952)
        {"uri": "/_layouts/15/emailPickerDialog.aspx?MultiSelect=true&AllowGroups=true", "method": "GET", "body": "", "referer": "/_layouts/15/settings.aspx"},
        # DataFormWebPart legitimate usage
        {"uri": "/_layouts/15/WebPartGallery.aspx", "method": "GET", "body": "", "referer": "/_layouts/15/settings.aspx"},
        # viewEdit.aspx (CVE-2019-1257)
        {"uri": f"/_layouts/15/viewEdit.aspx?List={list_guid}&View={view_guid}", "method": "GET", "body": "", "referer": "/_layouts/15/viewlsts.aspx"},
    ]

    endpoint = random.choice(vulnerable_endpoints)

    # Build request
    request_text = f"{endpoint['method']} {endpoint['uri']} HTTP/1.1\r\n"
    request_text += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
    request_text += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0\r\n"
    request_text += f"Referer: {endpoint['referer']}\r\n"
    request_text += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    request_text += f"Cookie: session_id={generator.get_session_cookie(src_ip)}\r\n"

    if endpoint["body"]:
        request_text += f"Content-Length: {len(endpoint['body'])}\r\n"
        request_text += "Content-Type: application/x-www-form-urlencoded\r\n"
        request_text += "\r\n"
        request_text += endpoint["body"]
    else:
        request_text += "\r\n"

    request = request_text.encode()

    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
    packets.append(pkt)
    conn.seq += len(request)
    current_time += exponential_delay(0.010, 0.050, 50)

    # Note: Generate realistic variable-size JSON response body
    # Generate realistic SharePoint JSON response
    json_response = generate_sharepoint_json_response("list_items", random.randint(3, 8))
    response_body = json.dumps(json_response).encode("utf-8")

    iis_version, aspnet_version = generator.get_server_versions(dst_ip)
    sp_build = random.randint(10000, 10500)  # Realistic SharePoint 2019/2021/SE builds

    response_text = "HTTP/1.1 200 OK\r\n"
    response_text += "Content-Type: application/json; charset=utf-8\r\n"  # JSON response for API data.
    response_text += f"Server: {iis_version}\r\n"
    response_text += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
    response_text += f"X-AspNet-Version: {aspnet_version}\r\n"
    response_text += f"SPRequestDuration: {generate_request_duration()}\r\n"
    response_text += "X-Powered-By: ASP.NET\r\n"
    response_text += f"MicrosoftSharePointTeamServices: 16.0.0.{sp_build}\r\n"
    response_text += f"Content-Length: {len(response_body)}\r\n"  # Use actual length
    response_text += "\r\n"

    response = response_text.encode() + response_body  # Add body to response

    pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response, current_time)
    packets.append(pkt)

    return packets


def generate_sharepoint_webpart_configuration_traffic(src_ip, dst_ip, sport, start_time):
    """Generate legitimate web part configuration requests"""
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 8080, current_time))
    current_time += random_pool.delay_handshake()

    conn = generator.get_connection(src_ip, dst_ip, sport, 8080)
    conn_server = generator.get_connection(dst_ip, src_ip, 8080, sport)

    # Generate random GUIDs for this request (realistic variability)
    generate_random_guid()
    generate_random_guid()

    # Legitimate web part configuration XML
    webpart_configs = [
        # Content Editor Web Part
        """<WebPart xmlns="http://schemas.microsoft.com/WebPart/v2">
  <Title>Announcements</Title>
  <FrameType>Default</FrameType>
  <Description>Displays recent site announcements</Description>
  <IsIncluded>true</IsIncluded>
  <ZoneID>LeftColumn</ZoneID>
  <PartOrder>2</PartOrder>
  <FrameState>Normal</FrameState>
  <Height />
  <Width />
  <AllowRemove>true</AllowRemove>
  <AllowZoneChange>true</AllowZoneChange>
  <AllowMinimize>true</AllowMinimize>
  <IsVisible>true</IsVisible>
  <DetailLink />
  <HelpLink />
  <Dir>Default</Dir>
  <PartImageSmall />
  <MissingAssembly>Cannot import this Web Part.</MissingAssembly>
  <IsIncludedFilter />
  <Assembly>Microsoft.SharePoint, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c</Assembly>
  <TypeName>Microsoft.SharePoint.WebPartPages.ContentEditorWebPart</TypeName>
  <ContentLink>~site/Documents/AnnouncementsContent.html</ContentLink>
  <Content><![CDATA[<div class="announcements-container"><h3>Recent Updates</h3></div>]]></Content>
</WebPart>""",
        # XsltListViewWebPart
        """<WebPart xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/WebPart/v2">
  <Title>Document Library</Title>
  <FrameType>Default</FrameType>
  <Description>Displays documents from the Shared Documents library</Description>
  <IsIncluded>true</IsIncluded>
  <ZoneID>MainZone</ZoneID>
  <PartOrder>1</PartOrder>
  <FrameState>Normal</FrameState>
  <Height />
  <Width />
  <AllowRemove>true</AllowRemove>
  <AllowZoneChange>true</AllowZoneChange>
  <AllowMinimize>true</AllowMinimize>
  <AllowConnect>true</AllowConnect>
  <AllowEdit>true</AllowEdit>
  <AllowHide>true</AllowHide>
  <IsVisible>true</IsVisible>
  <DetailLink />
  <HelpLink />
  <HelpMode>Modeless</HelpMode>
  <Dir>Default</Dir>
  <PartImageSmall />
  <MissingAssembly>Cannot import this Web Part.</MissingAssembly>
  <PartImageLarge>/_layouts/15/images/itdl.png</PartImageLarge>
  <IsIncludedFilter />
  <Assembly>Microsoft.SharePoint, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c</Assembly>
  <TypeName>Microsoft.SharePoint.WebPartPages.XsltListViewWebPart</TypeName>
  <ListDisplayName>Shared Documents</ListDisplayName>
  <ListName>{list_guid}</ListName>
  <ViewGuid>{view_guid}</ViewGuid>
  <ViewFlags>Html Hidden RecurrenceRowset</ViewFlags>
  <ViewType>Html</ViewType>
  <PageSize>30</PageSize>
</WebPart>""",
        # DataFormWebPart for list views
        """<WebPart xmlns="http://schemas.microsoft.com/WebPart/v2">
  <Title>Tasks Overview</Title>
  <FrameType>Default</FrameType>
  <Description>Displays current team tasks</Description>
  <IsIncluded>true</IsIncluded>
  <ZoneID>RightColumn</ZoneID>
  <PartOrder>3</PartOrder>
  <FrameState>Normal</FrameState>
  <AllowRemove>true</AllowRemove>
  <AllowZoneChange>true</AllowZoneChange>
  <IsVisible>true</IsVisible>
  <Assembly>Microsoft.SharePoint, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c</Assembly>
  <TypeName>Microsoft.SharePoint.WebPartPages.DataFormWebPart</TypeName>
  <ListName>{list_guid}</ListName>
  <ListDisplayName>Team Tasks</ListDisplayName>
  <ViewContentTypeId>0x</ViewContentTypeId>
  <DataSourceID>TasksDataSource</DataSourceID>
  <PageSize>20</PageSize>
  <UseSQLDataSourcePaging>True</UseSQLDataSourcePaging>
</WebPart>""",
    ]

    webpart_xml = random.choice(webpart_configs)

    # Build POST request with web part XML
    encoded_xml = urllib.parse.quote(webpart_xml, safe="")

    post_body = f"WebPartXml={encoded_xml}&SaveOption=Common&WebPartPageUrl=/SitePages/Home.aspx"

    request_text = "POST /_layouts/15/WebPartPages.aspx?Mode=AddWebPart HTTP/1.1\r\n"
    request_text += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
    request_text += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/118.0.0.0\r\n"
    request_text += "Referer: /_layouts/15/editpage.aspx\r\n"
    request_text += "Content-Type: application/x-www-form-urlencoded\r\n"
    request_text += f"Content-Length: {len(post_body)}\r\n"
    request_text += f"X-RequestDigest: {generate_request_digest()}\r\n"
    request_text += "\r\n"
    request_text += post_body

    request = request_text.encode()

    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
    packets.append(pkt)
    conn.seq += len(request)
    current_time += exponential_delay(0.010, 0.050, 50)

    iis_version, aspnet_version = generator.get_server_versions(dst_ip)

    # Note: Generate realistic variable-size XML response body
    response_body = b'<?xml version="1.0"?><WebPartDetails><Title>Web Part Configuration</Title>'
    response_body += b'<Property name="Height">400</Property>' * random.randint(2, 5)
    response_body += b'<Property name="Width">500</Property>' * random.randint(2, 5)
    response_body += b"</WebPartDetails>"

    response_text = "HTTP/1.1 200 OK\r\n"
    response_text += "Content-Type: application/xml; charset=utf-8\r\n"  # XML response for SOAP-style payloads.
    response_text += f"Server: {iis_version}\r\n"
    response_text += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
    response_text += f"SPRequestDuration: {generate_request_duration()}\r\n"
    response_text += f"Content-Length: {len(response_body)}\r\n"  # Use actual length
    response_text += "\r\n"

    response = response_text.encode() + response_body  # Add body to response

    pkt = create_tcp_psh_ack(dst_ip, src_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response, current_time)
    packets.append(pkt)

    return packets


def generate_http_sharepoint_traffic(
    start_time,
    duration,
    serializer: FastPacketSerializer | None = None,
    config: Config | None = None,
):
    """Generate HTTP traffic to SharePoint on port 8080"""
    logger.info("[+] Generating HTTP SharePoint traffic (port 8080)...")
    config = config or Config.from_defaults()

    use_serializer = serializer is not None
    all_packets = []

    # Regular HTTP sessions (API calls, page loads)
    current_time = start_time
    session_count = 0
    target_requests = int(duration * config.http_requests_per_sec)
    total_requests = 0

    while current_time < start_time + duration and total_requests < target_requests:
        # TIME-AWARE: Skip sessions during off-hours
        if not should_generate_packet(current_time):
            current_time += random.uniform(30, 120)  # Wait 30s-2min during off-hours
            continue

        # Choose user
        src_ip = random.choice(USER_WORKSTATION_IPS)
        sport = generator.allocate_port(src_ip)

        # Number of requests in this session (page load = 5-15 requests)
        num_requests = random.randint(5, 15)

        session_packets = generate_http_session(src_ip, SHAREPOINT_SERVER_IP, current_time, num_requests)
        all_packets.extend(session_packets)

        total_requests += num_requests
        session_count += 1

        # TIME-AWARE: Longer gaps during off-hours
        time_multiplier = get_time_of_day_multiplier(current_time)
        if time_multiplier < 0.3:
            current_time += random.uniform(10, 60)  # 10s-1min gaps at night
        else:
            current_time += random.uniform(1, 5)  # 1-5s gaps during business hours

    # Add HTTP file downloads - SPREAD ACROSS BUSINESS HOURS
    http_file_downloads = [ft for ft in FILE_TRANSFERS if ft[2] == "http"]
    download_count = 0

    for filename, filesize, _protocol, source, dest_ip in http_file_downloads[:10]:
        # Schedule downloads during business hours (8 AM - 6 PM)
        business_hours_start = 8 * 3600  # 8 AM in seconds
        business_hours_end = 18 * 3600  # 6 PM in seconds

        # Random time during business hours
        random_hour_offset = random.uniform(business_hours_start, business_hours_end)
        download_start = start_time + random_hour_offset

        sport = generator.allocate_port(dest_ip)

        logger.info(f"    HTTP download: {filename} ({filesize / 1024 / 1024:.1f} MB) -> {dest_ip}")

        simulated_size = min(filesize, 10_000_000)
        download_packets = generate_http_file_download(dest_ip, source, sport, filename, simulated_size, download_start)
        all_packets.extend(download_packets)
        download_count += 1

    # ADD LEGITIMATE VULNERABLE ENDPOINT TRAFFIC (BLENDING)
    logger.info("    Generating legitimate ToolPane and vulnerable endpoint requests (for blending)...")
    blend_count = 0

    # Generate 20-30 legitimate ToolPane.aspx requests
    for _ in range(random.randint(20, 30)):
        src_ip = random.choice(USER_WORKSTATION_IPS + ADMIN_WORKSTATION_IPS)
        sport = generator.allocate_port(src_ip)
        request_time = start_time + random.uniform(0, duration * 0.8)

        toolpane_packets = generate_legitimate_toolpane_requests(src_ip, SHAREPOINT_SERVER_IP, sport, request_time)
        all_packets.extend(toolpane_packets)
        blend_count += 1

    # Generate 15-20 requests to other historically vulnerable endpoints
    for _ in range(random.randint(15, 20)):
        src_ip = random.choice(USER_WORKSTATION_IPS + ADMIN_WORKSTATION_IPS)
        sport = generator.allocate_port(src_ip)
        request_time = start_time + random.uniform(0, duration * 0.8)

        vuln_packets = generate_legitimate_vulnerable_endpoint_requests(src_ip, SHAREPOINT_SERVER_IP, sport, request_time)
        all_packets.extend(vuln_packets)
        blend_count += 1

    # Generate 10-15 web part configuration requests
    for _ in range(random.randint(10, 15)):
        src_ip = random.choice(ADMIN_WORKSTATION_IPS)  # Only admins configure web parts
        sport = generator.allocate_port(src_ip)
        request_time = start_time + random.uniform(0, duration * 0.8)

        webpart_packets = generate_sharepoint_webpart_configuration_traffic(src_ip, SHAREPOINT_SERVER_IP, sport, request_time)
        all_packets.extend(webpart_packets)
        blend_count += 1

    logger.info(f"    Added {blend_count} legitimate vulnerable endpoint requests (blending traffic)")

    # Apply light retransmissions (3%) - POST-PROCESSING
    all_packets = apply_retransmissions_filtered(all_packets, RETRANSMISSION_RATE_OTHER)

    logger.info(
        f"    HTTP traffic: {len(all_packets)} packets ({session_count} sessions, {total_requests} requests, {download_count} file downloads, {blend_count} blending requests)"
    )

    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(all_packets)} HTTP packets to PCAP...")
        for pkt in all_packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return all_packets  # Return for backward compatibility


def generate_http_file_download_outbound(src_ip, dst_ip, sport, dport, domain, uri, size_mb, start_time):
    """
    Generate realistic HTTP file download from external source to SharePoint
    """
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, dport, current_time))
    current_time += random.uniform(0.01, 0.03)

    conn = generator.get_connection(src_ip, dst_ip, sport, dport)
    conn_server = generator.get_connection(dst_ip, src_ip, dport, sport)

    # HTTP GET request
    request = f"GET {uri} HTTP/1.1\r\n"
    request += f"Host: {domain}:{dport}\r\n"
    request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
    request += "Accept: application/octet-stream, */*\r\n"
    request += "Accept-Encoding: identity\r\n"
    request += "Connection: keep-alive\r\n"
    request += f"Referer: http://{domain}/\r\n"
    request += "\r\n"

    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, dport, conn.seq, conn.ack, 65535, request.encode(), current_time)
    packets.append(pkt)
    conn.seq += len(request)
    current_time += random.uniform(0.02, 0.05)

    # HTTP 200 OK response with Content-Length
    file_size_bytes = int(size_mb * 1024 * 1024)

    response_headers = "HTTP/1.1 200 OK\r\n"
    response_headers += "Content-Type: application/octet-stream\r\n"
    response_headers += f"Content-Length: {file_size_bytes}\r\n"
    response_headers += f'Content-Disposition: attachment; filename="{uri.split("/")[-1]}"\r\n'
    response_headers += "Accept-Ranges: bytes\r\n"
    response_headers += "Server: nginx/1.21.6\r\n"
    response_headers += "Connection: keep-alive\r\n"
    response_headers += "\r\n"

    pkt = create_tcp_psh_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn.seq, 65535, response_headers.encode(), current_time)
    packets.append(pkt)
    conn_server.seq += len(response_headers)
    current_time += random.uniform(0.005, 0.015)

    # Client ACK
    pkt = create_tcp_ack(src_ip, dst_ip, sport, dport, conn.seq, conn_server.seq, 65535, current_time)
    packets.append(pkt)
    current_time += random.uniform(0.005, 0.015)

    # Simulate file download in chunks (limit for PCAP size)
    chunk_sizes = [536, 892, 1024, 1380, 1400, 1448, 1460]
    chunk_size = random.choice(chunk_sizes)
    if random.random() < 0.15:  # 15% smaller fragments
        chunk_size = random.randint(200, 800)
    chunks_to_send = min(int(file_size_bytes / chunk_size), 200)  # Limit to ~300KB transfer

    for i in range(chunks_to_send):
        chunk_data = bytes([random.randint(0, 255) for _ in range(chunk_size)])
        pkt = create_tcp_psh_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn.seq, 65535, chunk_data, current_time)
        packets.append(pkt)
        conn_server.seq += chunk_size
        current_time += random.uniform(0.0001, 0.0005)

        # Client ACK every 10 packets
        if i % 10 == 0:
            pkt = create_tcp_ack(src_ip, dst_ip, sport, dport, conn.seq, conn_server.seq, 65535, current_time)
            packets.append(pkt)
            current_time += random.uniform(0.001, 0.003)

    # FIN handshake (reuse your existing tcp_fin_handshake function or create simple FIN exchange)

    return packets


def generate_sharepoint_outbound_software_downloads(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate realistic outbound HTTP traffic from SharePoint downloading software"""
    from ..config import DOMAIN_CONTROLLER_IP
    from .dns import generate_dns_query

    logger.info("[+] Generating SharePoint outbound software downloads with embedded attacker traffic...")

    use_serializer = serializer is not None
    all_packets = []

    # Software download sources (realistic mix).
    SOFTWARE_DOWNLOADS = [
        # (domain, IP, port, filename, size_mb, requests, file_type)
        # === SLACK ECOSYSTEM (Attacker Hidden Here!) ===
        ("downloads.slack.com", "203.0.113.20", 8080, "/windows/releases/slack-4.46.103-x64.exe", 125, 15, "exe"),
        ("cdn.slack-edge.com", "203.0.113.21", 8080, "/desktop-releases/windows/x64/4.46.102/slack-setup.exe", 118, 12, "exe"),
        ("downloads.slack-cdn.com", "203.0.113.22", 8080, "/Slack_4.46.104_x64.exe", 7.5, 5, "exe"),  # Recon source IP.
        ("files.slack.com", "203.0.113.23", 8080, "/slack-updates/Slack-4.46.101.exe", 120, 10, "exe"),
        # === MICROSOFT DOWNLOADS ===
        ("download.microsoft.com", "198.51.100.20", 8080, "/download/windows/teams-1.6.00.32062.exe", 156, 30, "exe"),
        ("software-download.microsoft.com", "198.51.100.21", 8080, "/download/pr/edge-setup-119.0.exe", 145, 9, "exe"),
        ("officecdn.microsoft.com", "198.51.100.22", 8080, "/pr/office365-2024-installer.exe", 3840, 15, "exe"),
        # === THIRD-PARTY SOFTWARE ===
        ("dl.google.com", "192.0.2.40", 8080, "/chrome/install/119.0.6045.160/chrome_installer.exe", 152, 11, "exe"),
        ("zoom.us", "192.0.2.41", 8080, "/client/5.16.10.24420/ZoomInstallerFull.exe", 95, 7, "exe"),
        ("download.mozilla.org", "192.0.2.42", 8080, "/pub/firefox/releases/119.0/win64/Firefox%20Setup%20119.0.exe", 74, 6, "exe"),
        # === CORPORATE SOFTWARE REPOS ===
        ("packages.company.com", "10.3.100.80", 8080, "/internal/zoom-installer-5.16.10.exe", 98, 7, "exe"),
        ("software-repo.local", "10.3.100.81", 8080, "/apps/chrome-enterprise-119.0.msi", 158, 10, "msi"),
        ("deploy.artifacts.local", "10.3.100.82", 8080, "/releases/vscode-1.84.2-x64-setup.exe", 92, 8, "exe"),
        # === DEVELOPER TOOLS ===
        ("github.com", "203.0.113.40", 8080, "/microsoft/vscode/releases/download/1.84.2/VSCodeUserSetup-x64-1.84.2.exe", 89, 5, "exe"),
        ("nodejs.org", "203.0.113.41", 8080, "/dist/v20.9.0/node-v20.9.0-x64.msi", 32, 4, "msi"),
        # === SYSTEM UTILITIES ===
        ("7-zip.org", "198.51.100.40", 8080, "/a/7z2301-x64.exe", 1.5, 3, "exe"),
        ("notepad-plus-plus.org", "198.51.100.41", 8080, "/repository/8.x/8.5.8/npp.8.5.8.Installer.x64.exe", 4.2, 3, "exe"),
        # === ADOBE PRODUCTS ===
        ("ardownload2.adobe.com", "192.0.2.50", 8080, "/installer/acrobat_dc_2024_installer.exe", 512, 8, "exe"),
        # === VIRTUALIZATION ===
        ("download3.vmware.com", "198.51.100.50", 8080, "/software/WKST-1750-WIN/VMware-workstation-17.5.0.exe", 680, 6, "exe"),
        ("download.virtualbox.org", "198.51.100.51", 8080, "/virtualbox/7.0.12/VirtualBox-7.0.12-159484-Win.exe", 104, 4, "exe"),
        # === COLLABORATION TOOLS ===
        ("aka.ms", "203.0.113.50", 8080, "/teams-windows-x64-installer", 156, 9, "exe"),
        ("downloads.webex.com", "203.0.113.51", 8080, "/WebexDesktop/Windows/43.10.0.25065/Webex.msi", 75, 5, "msi"),
    ]

    sharepoint_ip = SHAREPOINT_SERVER_IP  # 10.3.10.11
    dns_server = DOMAIN_CONTROLLER_IP  # 10.3.30.63

    logger.info(f"    Software download sources: {len(SOFTWARE_DOWNLOADS)}")
    logger.info("    [STEALTH] Attacker: downloads.slack-cdn.com (blended with Slack ecosystem)")

    total_downloads = 0

    for domain, resolved_ip, port, download_path, size_mb, request_count, _file_ext in SOFTWARE_DOWNLOADS:
        # Spread downloads throughout the day
        download_start = start_time + random.uniform(0, duration * 0.9)

        # DNS resolution before first download
        dns_time = download_start - random.uniform(1, 5)
        dns_packets = _generate_dns_query_response(sharepoint_ip, dns_server, domain, resolved_ip, dns_time, generate_dns_query)
        all_packets.extend(dns_packets)

        # Generate download requests
        for i in range(request_count):
            request_time = download_start + (i * random.uniform(300, 1800))  # Spread over time

            if request_time > start_time + duration:
                break

            sport = generator.allocate_port(sharepoint_ip)

            # Generate HTTP download
            download_packets = generate_http_file_download_outbound(sharepoint_ip, resolved_ip, sport, port, domain, download_path, size_mb, request_time)

            all_packets.extend(download_packets)
            total_downloads += 1

    logger.info(f"    Generated {len(all_packets):,} packets")
    logger.info(f"    Total software downloads: {total_downloads}")
    logger.info(f"    [STEALTH] Attacker downloads: 2 (blended with {len(SOFTWARE_DOWNLOADS)} sources)")
    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(all_packets)} Software Download packets to PCAP...")
        for pkt in all_packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return all_packets  # Return for backward compatibility


def _generate_dns_query_response(src_ip, dns_server, domain, resolved_ip, timestamp, generate_dns_query):
    """Generate DNS query and response pair"""
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    packets = []

    # DNS query
    query_pkt, txid, sport = generate_dns_query(src_ip, dns_server, domain, "A", timestamp)
    packets.append(query_pkt)

    # DNS response (20-80ms later)
    response_time = timestamp + random.uniform(0.020, 0.080)

    # Manually create response with resolved_ip
    pkt = Ether(src=generator.mac_table.get(dns_server, "00:00:00:00:00:02"), dst=generator.mac_table.get(src_ip, "00:00:00:00:00:01"))
    pkt /= IP(src=dns_server, dst=src_ip, id=random_pool.ip_id())
    pkt /= UDP(sport=53, dport=sport)
    pkt /= DNS(
        id=txid, qr=1, opcode=0, aa=0, rd=1, ra=1, rcode=0, qd=DNSQR(qname=domain, qtype="A"), an=DNSRR(rrname=domain, type="A", rdata=resolved_ip, ttl=300)
    )
    pkt.time = response_time
    packets.append(pkt)

    return packets


def generate_http_portal_traffic(
    start_time,
    duration,
    serializer: FastPacketSerializer | None = None,
    config: Config | None = None,
):
    """Compatibility wrapper for portal traffic."""
    return generate_http_sharepoint_traffic(start_time, duration, serializer=serializer, config=config)


def generate_portal_outbound_software_downloads(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Compatibility wrapper for outbound software downloads."""
    return generate_sharepoint_outbound_software_downloads(start_time, duration, serializer=serializer)


__all__ = [
    "generate_http_request_custom",
    "generate_http_response_body",
    "generate_http_response",
    "generate_http_file_download",
    "generate_http_session",
    "generate_legitimate_toolpane_requests",
    "generate_legitimate_vulnerable_endpoint_requests",
    "generate_sharepoint_webpart_configuration_traffic",
    "generate_http_sharepoint_traffic",
    "generate_http_file_download_outbound",
    "generate_sharepoint_outbound_software_downloads",
    "generate_http_portal_traffic",
    "generate_portal_outbound_software_downloads",
]
