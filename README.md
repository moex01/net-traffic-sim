# Network Traffic Simulator

net-traffic-sim generates synthetic large multi-day corporate network traffic PCAPs in few minutes. The traffic is designed to look realistic for training, detection testing, and CTF-style exercises.

It currently ships **35 protocol generators** including enterprise authentication (RADIUS) and time synchronization (NTP) (see `src/net_traffic_sim/protocols/__init__.py` `PROTOCOL_REGISTRY`).

## Protocol Categories

Protocols are organized into the following categories:

| Category | Protocols | Count |
|----------|-----------|-------|
| **Core Network** | ARP, ICMP, DHCP, DHCPv6, IPv6 ND, NTP | 6 |
| **Name Resolution & Discovery** | DNS (UDP), DNS_TCP, LLMNR, NBNS, mDNS, SSDP | 6 |
| **Web & API** | HTTP, HTTPS, QUIC, Software_Downloads | 4 |
| **Authentication & Directory** | Auth (Kerberos/LDAP), LDAPS, RADIUS | 3 |
| **Email** | SMTP, IMAP, POP3 | 3 |
| **Database** | SQL | 1 |
| **File Sharing** | SMB, FTP | 2 |
| **Remote Access** | RDP, SSH, WinRM, MSRPC | 4 |
| **VoIP** | VOIP (SIP/RTP) | 1 |
| **Monitoring & Logging** | SNMP, SYSLOG | 2 |
| **Security Testing** | Scanners, Targeted_Scanner | 2 |

**Total: 35 protocols**

### Recent Additions

**NTP Protocol (Network Time Synchronization):**
- NTPv4 time synchronization queries and responses
- Background polling with realistic intervals (64-1024s)
- NTP pool server queries (pool.ntp.org style)
- Stratum hierarchy support (primary/secondary/tertiary)
- RFC 5905 compliant packet structure

**RADIUS Protocol (Enterprise Authentication):**
- WiFi WPA2-Enterprise authentication flows
- VPN remote access authentication
- Multi-factor authentication (MFA) support
- Accounting (start/stop/interim-update)
- Challenge-Response authentication
- Access-Accept/Access-Reject flows

Key design points:
- Time-aware traffic patterns that reflect business-hour behavior.
- Fast generation using buffered writers and multiprocessing.
- Protocol-separated output PCAPs (merge them into a single capture with `mergecap`).

## Table of Contents
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Examples](#examples)
- [Notes](#notes)
- [Configuration](#configuration)
- [Developer API](#developer-api)
- [Docs](#docs)

## Requirements
- Python 3.10 and newer releases.
- Scapy 2.5.0+ (installed automatically via `pip` when you install the package).
- `mergecap` is required to merge the per-protocol PCAP files into a single capture; generation itself does not depend on `mergecap`.
- Linux, macOS, and Windows are supported as long as Scapy and `mergecap` are available; Windows users should add the Wireshark `bin` folder to their `PATH` so `mergecap.exe` can be invoked from the CLI.

## Install

```bash
git clone https://github.com/moex01/net-traffic-sim.git
cd net-traffic-sim
python -m pip install -e .
```

## Usage

### Environment setup
```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# Windows (PowerShell): .\.venv\Scripts\Activate.ps1

python -m pip install -e .
```

### CLI Flags & Options

**Required Arguments:**
- `--target-size <MB>` - Target size in megabytes for the generated PCAP
- `--duration <minutes>` - Duration of the simulated traffic in minutes

**Optional Flags:**
- `--output-dir <path>` - Output directory for PCAP files (default: `temp_pcaps/`)
- `--start-time <ISO8601>` - Start time for traffic simulation (default: current time)
- `--estimate-only` - Calculate estimated runtime without generating traffic
- `--dry-run` - Show what would be generated without creating files
- `--smoke` - Enable smoke test mode (limited SMB transfers for quick testing)
- `--verbose` - Enable detailed logging output for debugging
- `--checksums` - Generate valid checksums (slower, default is `--no-checksums`)
- `--no-merge` - Skip automatic mergecap operation
- `--keep-temps` - Keep individual protocol PCAP files after merging

**Note:** The simulator generates traffic for **all 35 protocols simultaneously** to create realistic corporate network traffic patterns. Protocol selection is not supported as the design goal is comprehensive network simulation.

**Examples:**
```bash
# Standard 12-hour capture with verbose logging
net-traffic-sim --target-size 500 --duration 720 --verbose

# Quick smoke test to verify everything works
net-traffic-sim --target-size 50 --duration 10 --smoke

# Estimate runtime before generating large capture
net-traffic-sim --estimate-only --target-size 2000 --duration 1440
```

### Recommended workflow
1. Generate protocol-separated PCAPs with the CLI (default output directory: `temp_pcaps/`).

```bash
net-traffic-sim --target-size 500 --duration 720 --output-dir temp_pcaps
```

2. Each run writes one PCAP per traffic stream in the output directory (e.g., `temp_pcaps/`). Merge them with `mergecap` to produce the final `final_output.pcap`, which contains all traffic sorted by timestamp.

```bash
mergecap -w final_output.pcap temp_pcaps/*.pcap
```

**Note**: You can use `--estimate-only` to verify sizing and run time before a long capture:

```bash
net-traffic-sim --estimate-only --target-size 1500 --duration 1440
```

## Examples

### Using Example Configurations

The `examples/` directory contains pre-configured YAML files for common scenarios:

```bash
# Enterprise network simulation (24-hour corporate traffic)
NET_TRAFFIC_SIM_CONFIG=examples/enterprise_network.yaml net-traffic-sim --target-size 1500 --duration 1440

# Security testing scenario (penetration test simulation)
NET_TRAFFIC_SIM_CONFIG=examples/security_testing.yaml net-traffic-sim --target-size 500 --duration 120

# VoIP call center simulation (8-hour shift)
NET_TRAFFIC_SIM_CONFIG=examples/voip_network.yaml net-traffic-sim --target-size 800 --duration 480
```

### Minimal example for a 10-minute capture (small, fast)
```bash
net-traffic-sim --target-size 50 --duration 10 --output-dir temp_pcaps --smoke
mergecap -w final_output.pcap temp_pcaps/*.pcap
```
Using `--smoke` limits SMB transfers (which normally takes time) and other heavy flows so short runs finish quickly for testing. Use it whenever you just want to confirm the CLI/serializer briefly.

### Example: 24-hour capture
```bash
net-traffic-sim --target-size 1500 --duration 1440 --output-dir 24h_pcaps
mergecap -w 24h_final.pcap 24h_pcaps/*.pcap
```
### Example: multi-day capture
```bash
net-traffic-sim --estimate-only --target-size 3000 --duration 4320
net-traffic-sim --target-size 3000 --duration 4320 --output-dir 3day_pcaps
mergecap -w 3day_final.pcap 3day_pcaps/*.pcap
```

## Notes
- Consider running `net-traffic-sim --estimate-only ...` before a large capture to verify the target size and runtime.
- `mergecap` is required only for the merge step; generation works without it.
- Default runs use `--no-checksums` for speed (Wireshark may show “bad checksum” warnings). Use `--checksums` for validated packets.
- Generated PCAPs are written under your output directory (default: `temp_pcaps/`). Delete `temp_pcaps*/` after runs if you don’t want to keep them.

## Configuration

The simulation is controlled by a configuration file. A default `config.json` is provided in the project root.

You can modify `config.json` to change:
- **Network Topology:** IP addresses, hostnames, and subnet prefixes.
- **Traffic Rates:** Volume of HTTP, SQL, DNS, SMB, and other protocols (e.g., `HTTP_REQUESTS_PER_SEC`).
- **Time Profiles:** Business hours vs. off-hours traffic multipliers.
- **Content Catalogs:** File lists for downloads, external domains for DNS, and scanner profiles.

### Loading a Custom Config
By default, the tool looks for `config.json` in the current directory. You can specify a different file using an environment variable:

```bash
NET_TRAFFIC_SIM_CONFIG=my_scenario.json net-traffic-sim --target-size 500 --duration 720
```

## Developer API

### BaseProtocol Abstract Class

The `BaseProtocol` class (`src/net_traffic_sim/protocols/base.py`) provides a foundation for building custom protocol simulators with common helper methods:

**Helper Methods:**
- `_validate_hosts(hosts)` - Ensures at least 2 hosts are available
- `_get_random_host_pair()` - Selects two random hosts for communication
- `_get_host_by_role(role)` - Finds a host with a specific role (e.g., 'server', 'dc', 'workstation')
- `_get_server_client_pair(server_role)` - Gets a client-server pair where server has a specific role
- `_generate_random_payload(min_size, max_size)` - Generates random payload bytes
- `_get_ephemeral_port()` - Returns a random ephemeral port (49152-65535)
- `_generate_tcp_handshake()` - Creates TCP SYN/SYN-ACK/ACK handshake packets
- `_generate_tcp_teardown()` - Creates TCP FIN handshake packets
- `_generate_tcp_data_exchange()` - Creates TCP request/response with ACKs

**Example Usage:**
```python
from net_traffic_sim.protocols.base import BaseProtocol

class CustomProtocol(BaseProtocol):
    def generate(self, serializer, start_time, duration_seconds):
        client, server = self._get_random_host_pair()
        sport = self._get_ephemeral_port()

        # Generate TCP connection
        packets = self._generate_tcp_handshake(
            client['ip'], server['ip'], sport, 8080, start_time
        )

        # Add your protocol-specific logic here
        payload = self._generate_random_payload(100, 500)
        # ... serialize packets ...
```

### Data Models

The `models.py` module provides data classes for configuration and results:

**ProtocolConfig** - Configuration for protocol generators
- `name: str` - Protocol name
- `enabled: bool` - Whether to generate this protocol (default: True)
- `packet_count: int` - Number of interactions to generate (0 = use CLI default)
- `custom_params: dict` - Optional protocol-specific parameters

**Host** - Network host configuration
- `ip: str` - IP address
- `mac: str | None` - MAC address (auto-generated if not provided)
- `role: str | None` - Host role ('server', 'client', 'dc', 'workstation', etc.)
- `hostname: str | None` - Optional hostname

**SimulationResult** - Traffic generation results
- `protocol: str` - Protocol name
- `packet_count: int` - Number of packets generated
- `duration_seconds: float` - Generation time
- `output_file: str | None` - Path to output PCAP

### Testing

The project uses pytest with parallel test execution via pytest-xdist for faster test runs.

**Running Tests:**
```bash
# Standard parallel test execution (recommended)
pytest -n auto

# Run tests with specific number of workers
pytest -n 4

# Run tests sequentially (slower)
pytest
```

**Performance Benchmarks (186 tests):**
- Sequential execution: ~150s
- 2 workers: ~77s (1.9x speedup)
- 4 workers: ~52s (2.9x speedup)
- Auto (12 workers): ~42s (3.6x speedup)

**Test Coverage:**
- 186 comprehensive tests covering all 35 protocols
- NTP: 14 dedicated tests for time synchronization flows
- RADIUS: 24 dedicated tests for enterprise authentication flows
- Core protocols: 148 tests for baseline network traffic
- All tests passing with parallel execution support

## Docs
Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand the project structure, how the orchestrator auto-configures, why traffic is generated per protocol, how `FastPacketSerializer` buffers writes, and how parallel workers coordinate.