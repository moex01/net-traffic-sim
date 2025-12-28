"""Scapy runtime configuration for faster offline packet generation."""

import logging

from scapy.all import conf  # type: ignore
from scapy.layers.inet import IP, TCP, UDP

_DEFAULT_IP_CHECK = conf.checkIPaddr
_DEFAULT_IP_SRC_CHECK = conf.checkIPsrc
_DEFAULT_IP_CHKSUM = IP.chksum
_DEFAULT_TCP_CHKSUM = TCP.chksum
_DEFAULT_UDP_CHKSUM = UDP.chksum


def configure_scapy(*, checksums: bool) -> None:
    """Configure Scapy behavior for packet generation."""
    conf.checkIPaddr = False
    conf.checkIPsrc = False
    conf.verb = 0

    if checksums:
        IP.chksum = _DEFAULT_IP_CHKSUM
        TCP.chksum = _DEFAULT_TCP_CHKSUM
        UDP.chksum = _DEFAULT_UDP_CHKSUM
    else:
        IP.chksum = 0  # type: ignore
        TCP.chksum = 0  # type: ignore
        UDP.chksum = 0  # type: ignore

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy").setLevel(logging.ERROR)


# Default behavior: checksums disabled for speed.
configure_scapy(checksums=False)
