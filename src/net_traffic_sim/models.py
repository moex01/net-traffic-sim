"""Data models for net-traffic-sim configuration and results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProtocolConfig:
    """Configuration for a specific protocol generator.

    Attributes:
        name: Protocol name (e.g., 'dns', 'http', 'smb')
        enabled: Whether this protocol should be generated
        packet_count: Number of protocol interactions to generate (0 = use CLI default)
        custom_params: Optional protocol-specific parameters
    """

    name: str
    enabled: bool = True
    packet_count: int = 0  # 0 means use default from CLI
    custom_params: dict[str, any] | None = None


@dataclass(frozen=True)
class Host:
    """Network host configuration.

    Attributes:
        ip: IP address of the host
        mac: MAC address (optional, will be auto-generated if not provided)
        role: Host role (e.g., 'server', 'client', 'dc', 'workstation')
        hostname: Optional hostname
    """

    ip: str
    mac: str | None = None
    role: str | None = None
    hostname: str | None = None


@dataclass(frozen=True)
class SimulationResult:
    """Result of traffic generation.

    Attributes:
        protocol: Protocol name
        packet_count: Number of packets generated
        duration_seconds: Time taken to generate
        output_file: Path to output PCAP file
    """

    protocol: str
    packet_count: int
    duration_seconds: float
    output_file: str | None = None
