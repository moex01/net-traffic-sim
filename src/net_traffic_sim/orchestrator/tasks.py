"""Task definitions and per-protocol writers."""

from __future__ import annotations

import os
import random
from dataclasses import dataclass

from ..config import ATTACKER_PUBLIC_IPS, WEB_APP_SERVER_IP, Config
from ..protocols import PROTOCOL_REGISTRY, generate_scanner_recon_requests
from ..serializer import FastPacketSerializer
from ..tcp import set_tcp_timestamp_base

GEN = PROTOCOL_REGISTRY


@dataclass(frozen=True)
class Task:
    name: str
    func: callable
    args: tuple
    description: str = ""


def create_protocol_writer(protocol_name: str, requires_config: bool = False):
    """Factory function to create a protocol writer function.

    Args:
        protocol_name: The key in PROTOCOL_REGISTRY for the protocol generator
        requires_config: Whether the protocol generator requires a config argument

    Returns:
        A writer function that generates traffic and writes to PCAP
    """

    def writer(start_time, duration, output_file, config=None, **kwargs):
        set_tcp_timestamp_base(start_time)
        serializer = FastPacketSerializer(output_file)
        try:
            call_kwargs = {"serializer": serializer, **kwargs}
            if requires_config:
                call_kwargs["config"] = config
            GEN[protocol_name](start_time, duration, **call_kwargs)
        finally:
            serializer.close()
        return serializer.packet_count, os.path.getsize(output_file)

    return writer


# Factory-generated protocol writers
generate_and_write_dns = create_protocol_writer("DNS", requires_config=True)
generate_and_write_dhcp = create_protocol_writer("DHCP")
generate_and_write_dhcpv6 = create_protocol_writer("DHCPv6")
generate_and_write_mdns = create_protocol_writer("mDNS")
generate_and_write_ssdp = create_protocol_writer("SSDP")
generate_and_write_llmnr = create_protocol_writer("LLMNR")
generate_and_write_nbns = create_protocol_writer("NBNS")
generate_and_write_ldaps = create_protocol_writer("LDAPS")
generate_and_write_winrm = create_protocol_writer("WinRM")
generate_and_write_msrpc = create_protocol_writer("MSRPC")
generate_and_write_dns_tcp = create_protocol_writer("DNS_TCP")
generate_and_write_ssh = create_protocol_writer("SSH")
generate_and_write_ftp = create_protocol_writer("FTP")
generate_and_write_syslog = create_protocol_writer("SYSLOG")
generate_and_write_quic = create_protocol_writer("QUIC")
generate_and_write_voip = create_protocol_writer("VOIP")
generate_and_write_ipv6_nd = create_protocol_writer("IPV6_ND")
generate_and_write_ntp = create_protocol_writer("NTP")
generate_and_write_snmp = create_protocol_writer("SNMP")
generate_and_write_smtp = create_protocol_writer("SMTP")
generate_and_write_imap = create_protocol_writer("IMAP")
generate_and_write_pop3 = create_protocol_writer("POP3")
generate_and_write_sql = create_protocol_writer("SQL", requires_config=True)
generate_and_write_arp = create_protocol_writer("ARP")
generate_and_write_http = create_protocol_writer("HTTP", requires_config=True)
generate_and_write_https = create_protocol_writer("HTTPS")
generate_and_write_rdp = create_protocol_writer("RDP")
generate_and_write_auth = create_protocol_writer("Auth")
generate_and_write_scanners = create_protocol_writer("Scanners")
generate_and_write_icmp = create_protocol_writer("ICMP")
generate_and_write_software_downloads = create_protocol_writer("Software_Downloads")


def generate_and_write_smb(
    start_time,
    duration,
    output_file,
    smb_size,
    max_transfers=None,
    enforce_short_run_caps=True,
):
    """Generate SMB traffic and write directly to PCAP (no memory storage!)."""
    set_tcp_timestamp_base(start_time)
    serializer = FastPacketSerializer(output_file)
    try:
        GEN["SMB"](
            start_time,
            duration,
            smb_simulated_size=smb_size,
            max_transfers=max_transfers,
            enforce_short_run_caps=enforce_short_run_caps,
            serializer=serializer,
        )
    finally:
        serializer.close()
    return serializer.packet_count, os.path.getsize(output_file)


def generate_and_write_targeted_scanner(start_time, duration, output_file):
    """Generate opportunistic scanner-style probes from a single IP."""
    set_tcp_timestamp_base(start_time)
    attack_time = start_time + random.uniform(duration * 0.3, duration * 0.7)
    attacker_ip = random.choice(ATTACKER_PUBLIC_IPS)
    packets = generate_scanner_recon_requests(
        attacker_ip,
        WEB_APP_SERVER_IP,
        "downloads.slack-cdn.com",
        attack_time,
        300,
    )
    serializer = FastPacketSerializer(output_file)
    try:
        for pkt in packets:
            serializer.add_packet(pkt, pkt.time)
    finally:
        serializer.close()
    return serializer.packet_count, os.path.getsize(output_file)


def build_tasks(
    start_time,
    duration,
    output_dir,
    smb_size,
    smb_max_transfers,
    smb_enforce_short_run_caps,
    config: Config,
):
    """Build task definitions for parallel traffic generation."""
    return [
        Task(
            "ARP",
            generate_and_write_arp,
            (start_time, duration, f"{output_dir}/00_arp.pcap"),
            "Always present (layer 2)",
        ),
        Task(
            "DNS",
            generate_and_write_dns,
            (start_time, duration, f"{output_dir}/01_dns.pcap", config),
            "Constant baseline",
        ),
        Task(
            "SQL",
            generate_and_write_sql,
            (start_time, duration, f"{output_dir}/02_sql.pcap", config),
            "Business hours heavy",
        ),
        Task(
            "HTTP",
            generate_and_write_http,
            (start_time, duration, f"{output_dir}/03_http.pcap", config),
            "Peak during 9AM-5PM",
        ),
        Task(
            "HTTPS",
            generate_and_write_https,
            (start_time, duration, f"{output_dir}/04_https.pcap"),
            "External browsing",
        ),
        Task(
            "SMB",
            generate_and_write_smb,
            (
                start_time,
                duration,
                f"{output_dir}/05_smb.pcap",
                smb_size,
                smb_max_transfers,
                smb_enforce_short_run_caps,
            ),
            "File transfers - business hours",
        ),
        Task(
            "Auth",
            generate_and_write_auth,
            (start_time, duration, f"{output_dir}/06_auth.pcap"),
            "Authentication - morning peak",
        ),
        Task(
            "LDAPS",
            generate_and_write_ldaps,
            (start_time, duration, f"{output_dir}/06b_ldaps.pcap"),
            "Secure directory binds",
        ),
        Task(
            "WinRM",
            generate_and_write_winrm,
            (start_time, duration, f"{output_dir}/06c_winrm.pcap"),
            "Admin WinRM/WMI activity",
        ),
        Task(
            "MSRPC",
            generate_and_write_msrpc,
            (start_time, duration, f"{output_dir}/06d_msrpc.pcap"),
            "RPC endpoint mapper + dynamic calls",
        ),
        Task(
            "Scanners",
            generate_and_write_scanners,
            (start_time, duration, f"{output_dir}/07_scanners.pcap"),
            "External scanners - constant",
        ),
        Task(
            "ICMP",
            generate_and_write_icmp,
            (start_time, duration, f"{output_dir}/08_icmp.pcap"),
            "Maintenance checks",
        ),
        Task(
            "Software_Downloads",
            generate_and_write_software_downloads,
            (start_time, duration, f"{output_dir}/09_downloads.pcap"),
            "Peak after patch Tuesdays",
        ),
        Task(
            "Targeted_Scanner",
            generate_and_write_targeted_scanner,
            (start_time, duration, f"{output_dir}/10_targeted_scanner.pcap"),
            "Opportunistic probes",
        ),
        Task(
            "DHCP",
            generate_and_write_dhcp,
            (start_time, duration, f"{output_dir}/11_dhcp.pcap"),
            "Lease churn and renewals",
        ),
        Task(
            "NTP",
            generate_and_write_ntp,
            (start_time, duration, f"{output_dir}/12_ntp.pcap"),
            "Time synchronization",
        ),
        Task(
            "SNMP",
            generate_and_write_snmp,
            (start_time, duration, f"{output_dir}/13_snmp.pcap"),
            "Monitoring polls",
        ),
        Task(
            "SMTP",
            generate_and_write_smtp,
            (start_time, duration, f"{output_dir}/14_smtp.pcap"),
            "Mail relay traffic",
        ),
        Task(
            "DHCPv6",
            generate_and_write_dhcpv6,
            (start_time, duration, f"{output_dir}/15_dhcpv6.pcap"),
            "IPv6 lease noise",
        ),
        Task(
            "mDNS",
            generate_and_write_mdns,
            (start_time, duration, f"{output_dir}/16_mdns.pcap"),
            "Endpoint multicast discovery",
        ),
        Task(
            "SSDP",
            generate_and_write_ssdp,
            (start_time, duration, f"{output_dir}/17_ssdp.pcap"),
            "UPnP discovery noise",
        ),
        Task(
            "IMAP",
            generate_and_write_imap,
            (start_time, duration, f"{output_dir}/18_imap.pcap"),
            "Mailbox access",
        ),
        Task(
            "POP3",
            generate_and_write_pop3,
            (start_time, duration, f"{output_dir}/19_pop3.pcap"),
            "Legacy mail access",
        ),
        Task(
            "LLMNR",
            generate_and_write_llmnr,
            (start_time, duration, f"{output_dir}/20_llmnr.pcap"),
            "Windows name resolution fallback",
        ),
        Task(
            "NBNS",
            generate_and_write_nbns,
            (start_time, duration, f"{output_dir}/21_nbns.pcap"),
            "NetBIOS name service noise",
        ),
        Task(
            "DNS_TCP",
            generate_and_write_dns_tcp,
            (start_time, duration, f"{output_dir}/22_dns_tcp.pcap"),
            "DNS over TCP (large responses)",
        ),
        Task(
            "SSH",
            generate_and_write_ssh,
            (start_time, duration, f"{output_dir}/23_ssh.pcap"),
            "Admin SSH/SFTP sessions",
        ),
        Task(
            "FTP",
            generate_and_write_ftp,
            (start_time, duration, f"{output_dir}/24_ftp.pcap"),
            "FTP/FTPS file transfers",
        ),
        Task(
            "SYSLOG",
            generate_and_write_syslog,
            (start_time, duration, f"{output_dir}/25_syslog.pcap"),
            "Syslog device reporting",
        ),
        Task(
            "QUIC",
            generate_and_write_quic,
            (start_time, duration, f"{output_dir}/26_quic.pcap"),
            "HTTP/3 QUIC browsing",
        ),
        Task(
            "VOIP",
            generate_and_write_voip,
            (start_time, duration, f"{output_dir}/27_voip.pcap"),
            "SIP signaling with RTP media",
        ),
        Task(
            "IPV6_ND",
            generate_and_write_ipv6_nd,
            (start_time, duration, f"{output_dir}/28_ipv6_nd.pcap"),
            "IPv6 neighbor discovery",
        ),
    ]
