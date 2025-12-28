"""Miscellaneous protocol traffic generators.

This module re-exports protocol generators from focused modules for
backward compatibility.
"""

from __future__ import annotations

# Discovery protocols
from .discovery import generate_ssdp_traffic

# Enterprise protocols
from .enterprise_misc import (
    generate_ldaps_traffic,
    generate_msrpc_traffic,
    generate_winrm_traffic,
)

# Mail protocols
from .mail import (
    generate_imap_traffic,
    generate_pop3_traffic,
    generate_smtp_traffic,
)

# Monitoring protocols
from .monitoring import (
    generate_snmp_traffic,
    generate_syslog_traffic,
)

# Network protocols
from .network import (
    generate_dhcp_traffic,
    generate_dhcpv6_traffic,
    generate_ipv6_nd_traffic,
    generate_ntp_traffic,
)

# QUIC protocol
from .quic import generate_quic_traffic

# Remote access protocols
from .remote import (
    generate_ftp_traffic,
    generate_ssh_traffic,
)

# VoIP protocols
from .voip import generate_sip_rtp_traffic

__all__ = [
    # Discovery
    "generate_ssdp_traffic",
    # Enterprise
    "generate_ldaps_traffic",
    "generate_winrm_traffic",
    "generate_msrpc_traffic",
    # Mail
    "generate_smtp_traffic",
    "generate_imap_traffic",
    "generate_pop3_traffic",
    # Monitoring
    "generate_syslog_traffic",
    "generate_snmp_traffic",
    # Network
    "generate_dhcp_traffic",
    "generate_dhcpv6_traffic",
    "generate_ipv6_nd_traffic",
    "generate_ntp_traffic",
    # QUIC
    "generate_quic_traffic",
    # Remote access
    "generate_ssh_traffic",
    "generate_ftp_traffic",
    # VoIP
    "generate_sip_rtp_traffic",
]
