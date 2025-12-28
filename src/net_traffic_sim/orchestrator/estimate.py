"""Estimation and auto-configuration utilities."""

from __future__ import annotations

import sys
from datetime import datetime

from ..config import (
    DHCP_LEASES_PER_HOUR,
    DNS_TCP_QUERIES_PER_HOUR,
    FILE_TRANSFERS,
    FTP_SESSIONS_PER_HOUR,
    IMAP_SESSIONS_PER_HOUR,
    IPV6_ND_EVENTS_PER_HOUR,
    LDAPS_SESSIONS_PER_HOUR,
    LLMNR_QUERIES_PER_HOUR,
    MSRPC_SESSIONS_PER_HOUR,
    NBNS_QUERIES_PER_HOUR,
    NTP_QUERIES_PER_HOUR,
    POP3_SESSIONS_PER_HOUR,
    PUBLIC_SCANNER_IPS,
    QUIC_SESSIONS_PER_HOUR,
    SIP_CALLS_PER_HOUR,
    SMTP_SESSIONS_PER_HOUR,
    SNMP_POLLS_PER_MINUTE,
    SSH_SESSIONS_PER_HOUR,
    SYSLOG_MESSAGES_PER_HOUR,
    WINRM_SESSIONS_PER_HOUR,
    Config,
)
from ..logging_setup import get_logger

logger = get_logger(__name__)

# Calibration multipliers keep estimator assumptions aligned with auto-config.
SQL_RATE_CALIBRATION = 0.6
HTTP_RATE_CALIBRATION = 0.7
DNS_HTTP_RATIO = 0.5


def calculate_pcap_size(packets):
    """Estimate PCAP file size."""
    total_bytes = 0
    for pkt in packets:
        total_bytes += 16 + len(bytes(pkt))

    total_bytes += 24
    return total_bytes


def auto_configure_for_target_size(
    target_size_mb,
    duration_seconds,
    allow_prompt=True,
    base_config: Config | None = None,
):
    """
    Automatically calculate optimal traffic rates to hit target size.
    Returns adjusted Config.
    """
    base_config = base_config or Config.from_defaults()
    logger.info(f"\n[*] Auto-configuring traffic rates for target size: {target_size_mb} MB...")

    if target_size_mb < 200:
        logger.info(f"    [!] WARNING: {target_size_mb} MB is very small for 24-hour capture!")
        logger.info("    [!] Minimum realistic size for 24h: ~200 MB")
        logger.info("    [!] Recommended sizes: 500 MB (minimal), 1 GB (normal), 2-5 GB (realistic)")
        if allow_prompt and sys.stdin.isatty():
            response = input(f"    Continue with {target_size_mb} MB anyway? [y/N]: ")
            if response.lower() not in ["y", "yes"]:
                logger.info("    [*] Cancelled. Please use --target-size with a larger value.")
                sys.exit(0)
        else:
            logger.info("    [!] Non-interactive mode: continuing with requested target size.")

    PROTOCOL_DISTRIBUTION = {
        "SMB": 0.68,
        "SQL": 0.13,
        "HTTP": 0.18,
        "HTTPS": 0.05,
        "DNS": 0.02,
        "Auth": 0.005,
        "Scanners": 0.002,
        "Other": 0.003,
    }
    distribution_total = sum(PROTOCOL_DISTRIBUTION.values())
    if distribution_total and distribution_total != 1.0:
        PROTOCOL_DISTRIBUTION = {key: value / distribution_total for key, value in PROTOCOL_DISTRIBUTION.items()}

    AVG_PACKET_SIZES = {
        "DNS": 120,
        "SQL": 450,
        "HTTP": 800,
        "HTTPS": 1200,
        "SMB": 1400,
    }

    target_bytes = target_size_mb * 1024 * 1024

    duration_hours = max(duration_seconds / 3600, 0.1)

    smb_target_bytes = target_bytes * PROTOCOL_DISTRIBUTION["SMB"]
    smb_entries = [ft for ft in FILE_TRANSFERS if ft[2] == "smb"]
    if duration_seconds <= 900:
        smb_transfer_cap = min(3, len(smb_entries))
        smb_simulated_cap_mb = 1
    elif duration_seconds <= 3600:
        smb_transfer_cap = min(5, len(smb_entries))
        smb_simulated_cap_mb = 3
    else:
        duration_transfer_cap = max(2, int(duration_seconds / 1800))
        smb_transfer_cap = min(15, duration_transfer_cap, len(smb_entries))
        smb_simulated_cap_mb = None

    num_smb_transfers = max(1, smb_transfer_cap)
    smb_bytes_per_transfer = smb_target_bytes / num_smb_transfers
    smb_simulated_mb = max(1, int(smb_bytes_per_transfer / (1024 * 1024)))
    if smb_simulated_cap_mb is not None:
        smb_simulated_mb = min(smb_simulated_mb, smb_simulated_cap_mb)

    sql_target_bytes = target_bytes * PROTOCOL_DISTRIBUTION["SQL"]
    sql_packets_per_query = 4
    sql_bytes_per_query = AVG_PACKET_SIZES["SQL"] * sql_packets_per_query
    sql_total_queries = int(sql_target_bytes / sql_bytes_per_query)
    num_sql_connections = 6
    sql_queries_per_sec = max(1, int((sql_total_queries / duration_seconds / num_sql_connections) / SQL_RATE_CALIBRATION))

    http_target_bytes = target_bytes * PROTOCOL_DISTRIBUTION["HTTP"]
    http_packets_per_session = 35
    http_bytes_per_session = AVG_PACKET_SIZES["HTTP"] * http_packets_per_session
    http_sessions = int(http_target_bytes / http_bytes_per_session)
    requests_per_session = 10
    http_requests_per_sec = int((http_sessions * requests_per_session / duration_seconds) / HTTP_RATE_CALIBRATION)

    dns_queries_per_sec = max(1, int(http_requests_per_sec * DNS_HTTP_RATIO))

    def _estimate_smb_bytes(simulated_mb, transfer_cap):
        simulated_bytes = simulated_mb * 1024 * 1024
        total = 0
        for _filename, filesize, _protocol, _source, _dest in smb_entries[:transfer_cap]:
            if filesize > 100_000_000:
                total += min(filesize, simulated_bytes)
            else:
                total += filesize
        return total

    estimated_smb_bytes = _estimate_smb_bytes(smb_simulated_mb, num_smb_transfers)
    http_packets_per_session = 35
    requests_per_session = 10
    http_bytes_per_request = AVG_PACKET_SIZES["HTTP"] * (http_packets_per_session / requests_per_session)
    estimated_http_requests = duration_seconds * http_requests_per_sec * HTTP_RATE_CALIBRATION
    http_download_bytes = sum(min(ft[1], 10_000_000) for ft in [ft for ft in FILE_TRANSFERS if ft[2] == "http"][:10])
    estimated_http_bytes = estimated_http_requests * http_bytes_per_request + http_download_bytes
    estimated_sql_queries = duration_seconds * sql_queries_per_sec * SQL_RATE_CALIBRATION
    estimated_sql_bytes = estimated_sql_queries * sql_bytes_per_query
    estimated_total_bytes = estimated_smb_bytes + estimated_sql_bytes + estimated_http_bytes

    if duration_hours <= 6 and estimated_total_bytes > 0:
        scale_factor = target_bytes / estimated_total_bytes
        if scale_factor > 1.15:
            scale_factor = min(scale_factor, 4.0)
            sql_queries_per_sec = max(1, int(sql_queries_per_sec * scale_factor))
            http_requests_per_sec = max(1, int(http_requests_per_sec * scale_factor))
            dns_queries_per_sec = max(1, int(http_requests_per_sec * DNS_HTTP_RATIO))
            logger.info(f"    [!] Short-run compensation: scaling SQL/HTTP rates by {scale_factor:.1f}x")

    if target_size_mb < 500:
        sql_queries_per_sec = max(1, sql_queries_per_sec)
        http_requests_per_sec = max(1, http_requests_per_sec)
        smb_simulated_mb = max(3, smb_simulated_mb)
        logger.info(f"    [!] Note: Small target size ({target_size_mb} MB) - using reduced minimum rates")
    else:
        sql_queries_per_sec = max(1, sql_queries_per_sec)
        http_requests_per_sec = max(5, http_requests_per_sec)
        smb_simulated_mb = max(10, smb_simulated_mb)
    if smb_simulated_cap_mb is not None:
        smb_simulated_mb = min(smb_simulated_mb, smb_simulated_cap_mb)

    config = base_config.with_overrides(
        sql_queries_per_sec=sql_queries_per_sec,
        http_requests_per_sec=http_requests_per_sec,
        dns_queries_per_sec=dns_queries_per_sec,
        smb_simulated_size_mb=smb_simulated_mb,
    )

    logger.info("    Auto-configured rates:")
    logger.info(f"      SQL_QUERIES_PER_SEC = {sql_queries_per_sec}")
    logger.info(f"      HTTP_REQUESTS_PER_SEC = {http_requests_per_sec}")
    logger.info(f"      DNS_QUERIES_PER_SEC = {dns_queries_per_sec}")
    logger.info(f"      SMB_SIMULATED_SIZE_MB = {smb_simulated_mb} MB per transfer")

    return config


def estimate_pcap_size_and_time(
    start_time,
    duration,
    target_size_mb,
    smb_simulated_size=None,
    smb_max_transfers=None,
    config: Config | None = None,
):
    """
    Estimate PCAP size and generation time BEFORE actually generating traffic.
    Returns: (estimated_size_mb, estimated_time_minutes)
    """
    config = config or Config.from_defaults()

    AVG_SIZES = {
        "DHCP": 320,
        "DHCPv6": 360,
        "DNS": 120,
        "mDNS": 200,
        "SSDP": 420,
        "LLMNR": 160,
        "NBNS": 140,
        "LDAPS": 900,
        "WinRM": 900,
        "MSRPC": 500,
        "DNS_TCP": 220,
        "SSH": 180,
        "FTP": 900,
        "SYSLOG": 180,
        "QUIC": 1200,
        "SIP/RTP": 300,
        "IPv6_ND": 140,
        "NTP": 90,
        "SNMP": 140,
        "SQL": 450,
        "HTTP": 800,
        "HTTPS": 1200,
        "SMB": 1400,
        "Auth": 250,
        "SMTP": 900,
        "IMAP": 900,
        "POP3": 500,
        "Scanners": 600,
        "ICMP/ARP": 100,
    }

    duration_seconds = duration
    duration_hours = duration / 3600

    estimates = {}

    dns_queries = int(duration_seconds * config.dns_queries_per_sec * 0.6)
    dns_packets = dns_queries * 2
    estimates["DNS"] = {
        "packets": dns_packets,
        "avg_size": AVG_SIZES["DNS"],
        "total_bytes": dns_packets * AVG_SIZES["DNS"],
    }

    dhcp_exchanges = max(1, int(duration_hours * DHCP_LEASES_PER_HOUR))
    dhcp_packets = dhcp_exchanges * 4
    estimates["DHCP"] = {
        "packets": dhcp_packets,
        "avg_size": AVG_SIZES["DHCP"],
        "total_bytes": dhcp_packets * AVG_SIZES["DHCP"],
    }

    dhcpv6_exchanges = max(1, int(duration_hours * DHCP_LEASES_PER_HOUR))
    dhcpv6_packets = dhcpv6_exchanges * 4
    estimates["DHCPv6"] = {
        "packets": dhcpv6_packets,
        "avg_size": AVG_SIZES["DHCPv6"],
        "total_bytes": dhcpv6_packets * AVG_SIZES["DHCPv6"],
    }

    mdns_queries = max(1, int(duration_seconds / 600))
    mdns_packets = mdns_queries * 2
    estimates["mDNS"] = {
        "packets": mdns_packets,
        "avg_size": AVG_SIZES["mDNS"],
        "total_bytes": mdns_packets * AVG_SIZES["mDNS"],
    }
    ssdp_queries = max(1, int(duration_seconds / 900))
    ssdp_packets = ssdp_queries * 2
    estimates["SSDP"] = {
        "packets": ssdp_packets,
        "avg_size": AVG_SIZES["SSDP"],
        "total_bytes": ssdp_packets * AVG_SIZES["SSDP"],
    }

    llmnr_queries = max(1, int(duration_hours * LLMNR_QUERIES_PER_HOUR))
    llmnr_packets = llmnr_queries * 2
    estimates["LLMNR"] = {
        "packets": llmnr_packets,
        "avg_size": AVG_SIZES["LLMNR"],
        "total_bytes": llmnr_packets * AVG_SIZES["LLMNR"],
    }
    nbns_queries = max(1, int(duration_hours * NBNS_QUERIES_PER_HOUR))
    nbns_packets = nbns_queries * 2
    estimates["NBNS"] = {
        "packets": nbns_packets,
        "avg_size": AVG_SIZES["NBNS"],
        "total_bytes": nbns_packets * AVG_SIZES["NBNS"],
    }

    ldaps_sessions = max(1, int(duration_hours * LDAPS_SESSIONS_PER_HOUR))
    ldaps_packets = ldaps_sessions * 24
    estimates["LDAPS"] = {
        "packets": ldaps_packets,
        "avg_size": AVG_SIZES["LDAPS"],
        "total_bytes": ldaps_packets * AVG_SIZES["LDAPS"],
    }

    winrm_sessions = max(1, int(duration_hours * WINRM_SESSIONS_PER_HOUR))
    winrm_packets = winrm_sessions * 28
    estimates["WinRM"] = {
        "packets": winrm_packets,
        "avg_size": AVG_SIZES["WinRM"],
        "total_bytes": winrm_packets * AVG_SIZES["WinRM"],
    }

    msrpc_sessions = max(1, int(duration_hours * MSRPC_SESSIONS_PER_HOUR))
    msrpc_packets = msrpc_sessions * 20
    estimates["MSRPC"] = {
        "packets": msrpc_packets,
        "avg_size": AVG_SIZES["MSRPC"],
        "total_bytes": msrpc_packets * AVG_SIZES["MSRPC"],
    }

    dns_tcp_queries = max(1, int(duration_hours * DNS_TCP_QUERIES_PER_HOUR))
    dns_tcp_packets = dns_tcp_queries * 6
    estimates["DNS_TCP"] = {
        "packets": dns_tcp_packets,
        "avg_size": AVG_SIZES["DNS_TCP"],
        "total_bytes": dns_tcp_packets * AVG_SIZES["DNS_TCP"],
    }

    ssh_sessions = max(1, int(duration_hours * SSH_SESSIONS_PER_HOUR))
    ssh_packets = ssh_sessions * 12
    estimates["SSH"] = {
        "packets": ssh_packets,
        "avg_size": AVG_SIZES["SSH"],
        "total_bytes": ssh_packets * AVG_SIZES["SSH"],
    }

    ftp_sessions = max(1, int(duration_hours * FTP_SESSIONS_PER_HOUR))
    ftp_packets = ftp_sessions * 20
    estimates["FTP"] = {
        "packets": ftp_packets,
        "avg_size": AVG_SIZES["FTP"],
        "total_bytes": ftp_packets * AVG_SIZES["FTP"],
    }

    syslog_messages = max(1, int(duration_hours * SYSLOG_MESSAGES_PER_HOUR))
    estimates["SYSLOG"] = {
        "packets": syslog_messages,
        "avg_size": AVG_SIZES["SYSLOG"],
        "total_bytes": syslog_messages * AVG_SIZES["SYSLOG"],
    }

    quic_sessions = max(1, int(duration_hours * QUIC_SESSIONS_PER_HOUR))
    quic_packets = quic_sessions * 5
    estimates["QUIC"] = {
        "packets": quic_packets,
        "avg_size": AVG_SIZES["QUIC"],
        "total_bytes": quic_packets * AVG_SIZES["QUIC"],
    }

    sip_calls = max(1, int(duration_hours * SIP_CALLS_PER_HOUR))
    sip_packets = sip_calls * 60
    estimates["SIP/RTP"] = {
        "packets": sip_packets,
        "avg_size": AVG_SIZES["SIP/RTP"],
        "total_bytes": sip_packets * AVG_SIZES["SIP/RTP"],
    }

    ipv6_events = max(1, int(duration_hours * IPV6_ND_EVENTS_PER_HOUR))
    ipv6_packets = ipv6_events * 2
    estimates["IPv6_ND"] = {
        "packets": ipv6_packets,
        "avg_size": AVG_SIZES["IPv6_ND"],
        "total_bytes": ipv6_packets * AVG_SIZES["IPv6_ND"],
    }

    ntp_queries = max(1, int(duration_hours * NTP_QUERIES_PER_HOUR))
    ntp_packets = ntp_queries * 2
    estimates["NTP"] = {
        "packets": ntp_packets,
        "avg_size": AVG_SIZES["NTP"],
        "total_bytes": ntp_packets * AVG_SIZES["NTP"],
    }

    snmp_polls = max(1, int((duration_seconds / 60) * SNMP_POLLS_PER_MINUTE))
    snmp_packets = snmp_polls * 2
    estimates["SNMP"] = {
        "packets": snmp_packets,
        "avg_size": AVG_SIZES["SNMP"],
        "total_bytes": snmp_packets * AVG_SIZES["SNMP"],
    }

    num_sql_connections = 6
    sql_packets_per_connection = int((duration_seconds * config.sql_queries_per_sec * 0.6) / num_sql_connections)
    sql_packets_per_query = 8
    total_sql_packets = sql_packets_per_connection * sql_packets_per_query * num_sql_connections
    estimates["SQL"] = {
        "packets": total_sql_packets,
        "avg_size": AVG_SIZES["SQL"],
        "total_bytes": total_sql_packets * AVG_SIZES["SQL"],
    }

    http_sessions = int((duration_seconds * config.http_requests_per_sec * 0.7) / 10)
    http_packets_per_session = 35
    total_http_packets = http_sessions * http_packets_per_session
    http_downloads = len([ft for ft in FILE_TRANSFERS if ft[2] == "http"][:10])
    http_download_packets = http_downloads * 8000
    total_http_packets += http_download_packets
    estimates["HTTP"] = {
        "packets": total_http_packets,
        "avg_size": AVG_SIZES["HTTP"],
        "total_bytes": total_http_packets * AVG_SIZES["HTTP"],
    }

    https_sessions = int(duration_hours * 30)
    https_packets_per_session = 45
    total_https_packets = https_sessions * https_packets_per_session
    estimates["HTTPS"] = {
        "packets": total_https_packets,
        "avg_size": AVG_SIZES["HTTPS"],
        "total_bytes": total_https_packets * AVG_SIZES["HTTPS"],
    }

    smb_transfers = min(25, len([ft for ft in FILE_TRANSFERS if ft[2] == "smb"]))
    duration_transfer_cap = max(2, int(duration_seconds / 1800))
    if smb_max_transfers is None:
        smb_transfers = min(smb_transfers, duration_transfer_cap, 15)
    else:
        smb_transfers = min(smb_transfers, smb_max_transfers)
    if smb_simulated_size is None:
        smb_simulated_size = config.smb_simulated_size_mb * 1024 * 1024
    smb_packets_per_transfer = int(smb_simulated_size / 1460) * 2
    total_smb_packets = smb_transfers * smb_packets_per_transfer
    estimates["SMB"] = {
        "packets": total_smb_packets,
        "avg_size": AVG_SIZES["SMB"],
        "total_bytes": total_smb_packets * AVG_SIZES["SMB"],
    }

    auth_requests = int(duration_hours * 60)
    auth_packets = auth_requests * 4
    estimates["Auth"] = {
        "packets": auth_packets,
        "avg_size": AVG_SIZES["Auth"],
        "total_bytes": auth_packets * AVG_SIZES["Auth"],
    }

    smtp_sessions = max(1, int(duration_hours * SMTP_SESSIONS_PER_HOUR))
    smtp_packets = smtp_sessions * 18
    estimates["SMTP"] = {
        "packets": smtp_packets,
        "avg_size": AVG_SIZES["SMTP"],
        "total_bytes": smtp_packets * AVG_SIZES["SMTP"],
    }

    imap_sessions = max(1, int(duration_hours * IMAP_SESSIONS_PER_HOUR))
    imap_packets = imap_sessions * 20
    estimates["IMAP"] = {
        "packets": imap_packets,
        "avg_size": AVG_SIZES["IMAP"],
        "total_bytes": imap_packets * AVG_SIZES["IMAP"],
    }

    pop3_sessions = max(1, int(duration_hours * POP3_SESSIONS_PER_HOUR))
    pop3_packets = pop3_sessions * 14
    estimates["POP3"] = {
        "packets": pop3_packets,
        "avg_size": AVG_SIZES["POP3"],
        "total_bytes": pop3_packets * AVG_SIZES["POP3"],
    }

    scanner_requests = len(PUBLIC_SCANNER_IPS) * 15
    scanner_packets = scanner_requests * 10
    estimates["Scanners"] = {
        "packets": scanner_packets,
        "avg_size": AVG_SIZES["Scanners"],
        "total_bytes": scanner_packets * AVG_SIZES["Scanners"],
    }

    num_ping_sessions = max(5, int(duration_seconds / 2160))
    num_external_pings = max(3, int(duration_seconds / 7200))
    icmp_arp_packets = (num_ping_sessions * 8) + (num_external_pings * 8) + 30
    estimates["ICMP/ARP"] = {
        "packets": icmp_arp_packets,
        "avg_size": AVG_SIZES["ICMP/ARP"],
        "total_bytes": icmp_arp_packets * AVG_SIZES["ICMP/ARP"],
    }

    total_packets = sum(est["packets"] for est in estimates.values())
    total_bytes = sum(est["total_bytes"] for est in estimates.values())

    pcap_overhead = 24 + (total_packets * 16)
    total_bytes_with_overhead = total_bytes + pcap_overhead
    total_mb_with_overhead = total_bytes_with_overhead / (1024 * 1024)

    generation_rates = {
        "DHCP": 12000,
        "DHCPv6": 12000,
        "DNS": 10000,
        "mDNS": 12000,
        "SSDP": 12000,
        "LLMNR": 12000,
        "NBNS": 12000,
        "DNS_TCP": 8000,
        "SSH": 8000,
        "FTP": 6000,
        "SYSLOG": 12000,
        "QUIC": 10000,
        "SIP/RTP": 8000,
        "IPv6_ND": 12000,
        "NTP": 12000,
        "SNMP": 12000,
        "SQL": 3000,
        "HTTP": 5000,
        "HTTPS": 4000,
        "SMB": 8000,
        "Auth": 8000,
        "SMTP": 4000,
        "IMAP": 4000,
        "POP3": 4000,
        "Scanners": 5000,
        "ICMP/ARP": 15000,
    }

    generation_times = {}
    for protocol, est in estimates.items():
        rate = generation_rates.get(protocol, 5000)
        time_seconds = est["packets"] / rate
        generation_times[protocol] = time_seconds

    longest_task_time = max(generation_times.values())
    total_time_minutes = longest_task_time / 60

    logger.info("\n" + "=" * 70)
    logger.info("PCAP ESTIMATION")
    logger.info("=" * 70)
    logger.info(f"Target size:        {target_size_mb} MB")
    logger.info(f"Estimated size:     {total_mb_with_overhead:.0f} MB")
    logger.info(f"Estimated packets:  {total_packets:,}")
    logger.info(f"Estimated time:     {total_time_minutes:.1f} minutes")

    size_diff = total_mb_with_overhead - target_size_mb
    if abs(size_diff) > target_size_mb * 0.3:
        if size_diff > 0:
            logger.info(f"[!] Warning: Will generate ~{size_diff:.0f} MB more than target")
        else:
            logger.info(f"[!] Warning: Will generate ~{abs(size_diff):.0f} MB less than target")

    logger.info("=" * 70)

    return total_mb_with_overhead, total_time_minutes


def print_dry_run_plan(start_time, duration, target_size_mb, config: Config | None = None):
    """Print dry-run plan without generating traffic."""
    config = config or Config.from_defaults()
    logger.info("\n" + "=" * 70)
    logger.info("DRY RUN MODE - No PCAP will be generated")
    logger.info("=" * 70)
    logger.info(f"\nStart time: {datetime.fromtimestamp(start_time)}")
    logger.info(f"Duration: {duration // 60} minutes ({duration} seconds)")
    logger.info(f"Target size: {target_size_mb} MB")

    logger.info("\nPlanned traffic generation:")
    logger.info(f"  - DNS: ~{int(duration * config.dns_queries_per_sec)} queries")
    logger.info(f"  - SQL: 6-8 connections, ~{int(duration * config.sql_queries_per_sec)} queries")
    logger.info(f"  - RDP: 2-3 sessions, ~{int(duration * 8)} exchanges")
    logger.info(f"  - HTTP/HTTPS: ~{int(duration * config.http_requests_per_sec)} requests")
    logger.info("  - SMB: 18 file transfers (varied sizes)")
    logger.info(f"  - Kerberos/LDAP: ~{int(duration * 0.2)} authentications")
    logger.info("  - Targeted scanner: ~25 requests (opportunistic probes)")
    logger.info("  - ICMP/ARP: ~100 packets")

    estimated_packets = int(duration * 300)
    estimated_size = (estimated_packets * 500) / (1024 * 1024)

    logger.info("\nEstimated output:")
    logger.info(f"  - Total packets: ~{estimated_packets:,}")
    logger.info(f"  - File size: ~{estimated_size:.0f} MB")
    logger.info(f"  - Average rate: ~{estimated_packets / duration:.0f} packets/second")
    logger.info("\n" + "=" * 70)
