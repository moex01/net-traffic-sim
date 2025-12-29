"""Protocol-specific traffic generators for the synthetic environment."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..config import (
    DOMAIN_CONTROLLER_IP,
    SHAREPOINT_HOSTNAME,
    SHAREPOINT_SERVER_IP,
)
from ..helpers import (
    format_guid_for_url,
    generate_random_guid,
    generate_request_digest,
    generate_request_duration,
    generate_sharepoint_health_score,
    generate_sharepoint_json_response,
    generate_sharepoint_list_guid,
    generate_view_guid,
)
from ..logging_setup import get_logger
from ..state import generator, get_mac_fast, random_pool
from ..tcp import (
    create_tcp_ack,
    create_tcp_psh_ack,
    exponential_delay,
    tcp_handshake,
)
from .dns import generate_dns_query_response
from .http import (
    generate_http_file_download_outbound,
)

logger = get_logger(__name__)


# ---
# LEGITIMATE SHAREPOINT VULNERABLE ENDPOINT TRAFFIC (BLENDING)
# ---
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
    import urllib.parse

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
    import json

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
    import urllib.parse

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


def generate_sharepoint_outbound_software_downloads(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Generate realistic outbound HTTP traffic from SharePoint downloading software"""
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
        dns_packets = generate_dns_query_response(sharepoint_ip, dns_server, domain, resolved_ip, dns_time)
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


# ---
# ADDITIONAL PROTOCOL HELPERS (imported from base.py for local use)
# ---
def _emit_packet(
    serializer: FastPacketSerializer | None,
    packets: list,
    pkt,
    timestamp: float,
) -> None:
    """Emit packet to serializer or list."""
    if serializer is not None:
        serializer.add_packet(pkt, timestamp)
    else:
        packets.append(pkt)


def _udp_packet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
    timestamp: float,
    dst_mac: str | None = None,
):
    """Create UDP IPv4 packet."""
    if dst_mac is None:
        dst_mac = get_mac_fast(dst_ip)
    pkt = Ether(src=get_mac_fast(src_ip), dst=dst_mac)
    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id(src_ip, dst_ip))
    pkt /= UDP(sport=sport, dport=dport)
    if payload:
        pkt /= Raw(load=payload)
    pkt.time = timestamp
    return pkt


def _udp6_packet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
    timestamp: float,
    dst_mac: str | None = None,
):
    """Create UDP IPv6 packet."""
    if dst_mac is None:
        dst_mac = "33:33:00:00:00:01"
    pkt = Ether(src=get_mac_fast(src_ip), dst=dst_mac)
    pkt /= IPv6(src=src_ip, dst=dst_ip)
    pkt /= UDP(sport=sport, dport=dport)
    if payload:
        pkt /= Raw(load=payload)
    pkt.time = timestamp
    return pkt


def _simple_tcp_exchange(
    src_ip: str,
    dst_ip: str,
    dport: int,
    start_time: float,
    payload: bytes | str,
    response_payload: bytes | str | None = None,
):
    packets = []
    sport = random_pool.port()
    handshake = tcp_handshake(src_ip, dst_ip, sport, dport, start_time)
    packets.extend(handshake)

    syn = handshake[0]
    syn_ack = handshake[1]
    conn_client = generator.get_connection(src_ip, dst_ip, sport, dport)
    conn_server = generator.get_connection(dst_ip, src_ip, dport, sport)
    conn_server.seq = syn_ack[TCP].seq + 1
    conn_server.ack = syn[TCP].seq + 1
    conn_server.established = True

    current_time = handshake[-1].time + random_pool.delay_small()
    if payload:
        if isinstance(payload, str):
            payload = payload.encode("ascii", "ignore")
        pkt = create_tcp_psh_ack(
            src_ip,
            dst_ip,
            sport,
            dport,
            conn_client.seq,
            conn_client.ack,
            65535,
            payload,
            current_time,
        )
        packets.append(pkt)
        conn_client.seq += len(payload)
        current_time += random_pool.delay_small()
        ack = create_tcp_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn_client.seq, 65535, current_time)
        packets.append(ack)

    if response_payload:
        current_time += random_pool.delay_small()
        if isinstance(response_payload, str):
            response_payload = response_payload.encode("ascii", "ignore")
        resp = create_tcp_psh_ack(
            dst_ip,
            src_ip,
            dport,
            sport,
            conn_server.seq,
            conn_client.seq,
            65535,
            response_payload,
            current_time,
        )
        packets.append(resp)
        conn_server.seq += len(response_payload)
        current_time += random_pool.delay_small()
        ack2 = create_tcp_ack(src_ip, dst_ip, sport, dport, conn_client.seq, conn_server.seq, 65535, current_time)
        packets.append(ack2)

    return packets


def generate_portal_outbound_software_downloads(start_time, duration, serializer: FastPacketSerializer | None = None):
    """Compatibility wrapper for outbound software downloads."""
    return generate_sharepoint_outbound_software_downloads(start_time, duration, serializer=serializer)


# ---
# MAIN ORCHESTRATION AND PCAP GENERATION
# ---
