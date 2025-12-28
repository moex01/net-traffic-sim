from __future__ import annotations

from .auth import generate_kerberos_ldap_traffic
from .discovery import (
    generate_llmnr_traffic,
    generate_mdns_traffic,
    generate_nbns_traffic,
    generate_ssdp_traffic,
)
from .dns import generate_dns_tcp_traffic, generate_dns_traffic
from .http import (
    generate_http_portal_traffic,
    generate_portal_outbound_software_downloads,
)
from .https import generate_https_external_traffic
from .icmp import generate_arp_traffic, generate_icmp_arp_traffic
from .misc import (
    generate_dhcp_traffic,
    generate_dhcpv6_traffic,
    generate_ftp_traffic,
    generate_imap_traffic,
    generate_ipv6_nd_traffic,
    generate_ldaps_traffic,
    generate_msrpc_traffic,
    generate_ntp_traffic,
    generate_pop3_traffic,
    generate_quic_traffic,
    generate_sip_rtp_traffic,
    generate_smtp_traffic,
    generate_snmp_traffic,
    generate_ssh_traffic,
    generate_syslog_traffic,
    generate_winrm_traffic,
)
from .rdp import generate_rdp_traffic
from .scanners import (
    generate_public_scanner_traffic,
    generate_scanner_recon_requests,
)
from .smb import generate_smb_traffic
from .sql import generate_sql_traffic

PROTOCOL_REGISTRY = {
    "ARP": generate_arp_traffic,
    "DNS": generate_dns_traffic,
    "SQL": generate_sql_traffic,
    "HTTP": generate_http_portal_traffic,
    "HTTPS": generate_https_external_traffic,
    "SMB": generate_smb_traffic,
    "Auth": generate_kerberos_ldap_traffic,
    "LDAPS": generate_ldaps_traffic,
    "WinRM": generate_winrm_traffic,
    "MSRPC": generate_msrpc_traffic,
    "Scanners": generate_public_scanner_traffic,
    "RDP": generate_rdp_traffic,
    "ICMP": generate_icmp_arp_traffic,
    "Software_Downloads": generate_portal_outbound_software_downloads,
    "Targeted_Scanner": generate_scanner_recon_requests,
    "DHCP": generate_dhcp_traffic,
    "NTP": generate_ntp_traffic,
    "SNMP": generate_snmp_traffic,
    "SMTP": generate_smtp_traffic,
    "DHCPv6": generate_dhcpv6_traffic,
    "mDNS": generate_mdns_traffic,
    "SSDP": generate_ssdp_traffic,
    "IMAP": generate_imap_traffic,
    "POP3": generate_pop3_traffic,
    "LLMNR": generate_llmnr_traffic,
    "NBNS": generate_nbns_traffic,
    "DNS_TCP": generate_dns_tcp_traffic,
    "SSH": generate_ssh_traffic,
    "FTP": generate_ftp_traffic,
    "SYSLOG": generate_syslog_traffic,
    "QUIC": generate_quic_traffic,
    "VOIP": generate_sip_rtp_traffic,
    "IPV6_ND": generate_ipv6_nd_traffic,
}

__all__ = [
    "PROTOCOL_REGISTRY",
    "generate_arp_traffic",
    "generate_dns_traffic",
    "generate_sql_traffic",
    "generate_http_portal_traffic",
    "generate_https_external_traffic",
    "generate_smb_traffic",
    "generate_kerberos_ldap_traffic",
    "generate_ldaps_traffic",
    "generate_winrm_traffic",
    "generate_msrpc_traffic",
    "generate_public_scanner_traffic",
    "generate_rdp_traffic",
    "generate_icmp_arp_traffic",
    "generate_portal_outbound_software_downloads",
    "generate_scanner_recon_requests",
    "generate_dhcp_traffic",
    "generate_ntp_traffic",
    "generate_snmp_traffic",
    "generate_smtp_traffic",
    "generate_dhcpv6_traffic",
    "generate_mdns_traffic",
    "generate_ssdp_traffic",
    "generate_imap_traffic",
    "generate_pop3_traffic",
    "generate_llmnr_traffic",
    "generate_nbns_traffic",
    "generate_dns_tcp_traffic",
    "generate_ssh_traffic",
    "generate_ftp_traffic",
    "generate_syslog_traffic",
    "generate_quic_traffic",
    "generate_sip_rtp_traffic",
    "generate_ipv6_nd_traffic",
]
