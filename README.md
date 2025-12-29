# Network Traffic Simulator

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 186 passing](https://img.shields.io/badge/tests-186%20passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**net-traffic-sim** generates synthetic large-scale multi-day corporate network traffic PCAPs in a few minutes. The traffic is designed to look realistic for security training, detection system testing, and CTF-style exercises.

It currently ships **35 protocol generators** including enterprise authentication (RADIUS), time synchronization (NTP), and comprehensive attack simulation capabilities.

## Table of Contents
- [Features](#features)
- [Supported Protocols](#supported-protocols)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Configuration](#configuration)
- [Performance & Scalability](#performance--scalability)
- [Security Considerations](#security-considerations)
- [Developer Guide](#developer-guide)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [License](#license)

## Features

### Key Differentiators
- **Fast multi-core generation**: Utilizes multiprocessing for ~3.5x faster PCAP generation
- **35 protocol generators**: Comprehensive coverage across application, network, and security layers
- **Realistic traffic patterns**: Time-aware behavior reflecting business hours vs. off-hours activity
- **Attack simulation**: Includes scanner reconnaissance and targeted attack traffic
- **CTF-ready**: Designed for security training, blue team exercises, and CTF challenge creation
- **Flexible configuration**: YAML/JSON support with environment variable overrides
- **Protocol-separated output**: Individual PCAPs per protocol stream, merged via `mergecap`

### Traffic Realism
- Business-hour-aware traffic multipliers
- Realistic protocol interactions (DNS lookups before HTTP, TCP handshakes, etc.)
- Enterprise patterns (Kerberos/LDAP authentication, SharePoint workflows, VoIP calls)
- Scanner and attacker simulation with reconnaissance phases
- Multi-factor authentication (MFA) flows for modern enterprise environments

## Supported Protocols

| Category | Protocols | Count | Standards/RFCs |
|----------|-----------|-------|----------------|
| **Core Network** | ARP, ICMP, DHCP, DHCPv6, IPv6 ND, NTP | 6 | RFC 5905 (NTP), RFC 2131 (DHCP) |
| **Name Resolution & Discovery** | DNS (UDP), DNS_TCP, LLMNR, NBNS, mDNS, SSDP | 6 | RFC 1035 (DNS), RFC 4795 (LLMNR) |
| **Web & API** | HTTP, HTTPS, QUIC, Software_Downloads | 4 | RFC 9114 (HTTP/3), RFC 2616 (HTTP/1.1) |
| **Authentication & Directory** | Auth (Kerberos/LDAP), LDAPS, RADIUS | 3 | RFC 2865 (RADIUS), RFC 4120 (Kerberos) |
| **Email** | SMTP, IMAP, POP3 | 3 | RFC 5321 (SMTP), RFC 3501 (IMAP) |
| **Database** | SQL (TDS protocol) | 1 | MS-TDS specification |
| **File Sharing** | SMB, FTP | 2 | SMB2/SMB3, RFC 959 (FTP) |
| **Remote Access** | RDP, SSH, WinRM, MSRPC | 4 | RFC 4254 (SSH) |
| **VoIP** | VOIP (SIP/RTP) | 1 | RFC 3261 (SIP), RFC 3550 (RTP) |
| **Monitoring & Logging** | SNMP, SYSLOG | 2 | RFC 3411 (SNMP), RFC 5424 (Syslog) |
| **Security Testing** | Scanners, Targeted_Scanner | 2 | Attack simulation |

**Total: 35 protocols**

### Recent Additions

**NTP Protocol (Network Time Synchronization):**
- NTPv4 time synchronization queries and responses
- Background polling with realistic intervals (64-1024s)
- NTP pool server queries (pool.ntp.org style)
- Stratum hierarchy support (primary/secondary/tertiary)
- [RFC 5905](https://datatracker.ietf.org/doc/html/rfc5905) compliant packet structure

**RADIUS Protocol (Enterprise Authentication):**
- WiFi WPA2-Enterprise authentication flows
- VPN remote access authentication
- Multi-factor authentication (MFA) support
- Accounting (start/stop/interim-update)
- Challenge-Response authentication
- Access-Accept/Access-Reject flows

## Quick Start

Generate a small test capture to verify installation:

```bash
# Clone and install
git clone https://github.com/moex01/net-traffic-sim.git
cd net-traffic-sim
python -m pip install -e .

# Generate 10-minute test capture
net-traffic-sim --target-size 50 --duration 10 --smoke --output-dir temp_pcaps

# Merge into single PCAP
mergecap -w final_output.pcap temp_pcaps/*.pcap
```

**Expected output:**
- Individual protocol PCAPs in `temp_pcaps/` directory
- Merged `final_output.pcap` containing all traffic sorted by timestamp
- ~50 MB total PCAP size with traffic from all 35 protocols

**Verify:**
```bash
# View PCAP statistics
tshark -r final_output.pcap -q -z io,phs
```

## Installation

### Prerequisites
- **Python 3.10+** - Required for modern type hints and syntax
- **Scapy 2.5.0+** - Installed automatically via pip
- **Wireshark tools** - `mergecap` and `tshark` for PCAP merging and analysis
  - macOS: `brew install wireshark`
  - Ubuntu/Debian: `sudo apt install wireshark-common`
  - Windows: Install [Wireshark](https://www.wireshark.org/download.html) and add `C:\Program Files\Wireshark` to PATH

### Installation Steps

```bash
# Clone repository
git clone https://github.com/moex01/net-traffic-sim.git
cd net-traffic-sim

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# Windows (PowerShell): .\.venv\Scripts\Activate.ps1

# Install package in editable mode
python -m pip install -e .
```

### Verification

```bash
# Check installation
net-traffic-sim --help

# Verify mergecap is available
mergecap -v
```

## Usage

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

**Important:** The simulator generates traffic for all 35 protocols simultaneously to create realistic corporate network traffic patterns. This design ensures comprehensive network simulation that mirrors real enterprise environments.

### Basic Commands

```bash
# Standard 12-hour capture with verbose logging
net-traffic-sim --target-size 500 --duration 720 --verbose

# Quick smoke test to verify everything works
net-traffic-sim --target-size 50 --duration 10 --smoke

# Estimate runtime before generating large capture
net-traffic-sim --estimate-only --target-size 2000 --duration 1440
```

## Examples

### Minimal Example (10-minute test)

```bash
net-traffic-sim --target-size 50 --duration 10 --output-dir temp_pcaps --smoke
mergecap -w final_output.pcap temp_pcaps/*.pcap
```

Using `--smoke` limits resource-intensive protocols (SMB transfers, large downloads) for quick testing.

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

### Multi-Day Capture

```bash
# Estimate first
net-traffic-sim --estimate-only --target-size 3000 --duration 4320

# Generate 3-day capture
net-traffic-sim --target-size 3000 --duration 4320 --output-dir 3day_pcaps
mergecap -w 3day_final.pcap 3day_pcaps/*.pcap
```

For complete examples, see the `examples/` directory for YAML configuration templates.

## Configuration

The simulation is controlled by configuration files in YAML or JSON format. A default `config.json` is provided in the project root.

### Configuration File Format

Both YAML and JSON formats are supported:
- `config.json` - Default JSON configuration
- `config.yaml` or `config.yml` - YAML alternative
- Custom files via `NET_TRAFFIC_SIM_CONFIG` environment variable

### Configuration Options

Modify configuration files to customize:
- **Network Topology:** IP addresses, hostnames, and subnet prefixes
- **Traffic Rates:** Volume of HTTP, SQL, DNS, SMB, and other protocols (e.g., `HTTP_REQUESTS_PER_SEC`)
- **Time Profiles:** Business hours vs. off-hours traffic multipliers
- **Content Catalogs:** File lists for downloads, external domains for DNS, scanner profiles

### Configuration Precedence

Configuration is loaded in the following order (later overrides earlier):
1. Default built-in values
2. Configuration file (`config.json` or specified via environment variable)
3. Environment variables (for specific overrides)

### Loading a Custom Config

```bash
# Using JSON
NET_TRAFFIC_SIM_CONFIG=my_scenario.json net-traffic-sim --target-size 500 --duration 720

# Using YAML
NET_TRAFFIC_SIM_CONFIG=my_scenario.yaml net-traffic-sim --target-size 500 --duration 720
```

See `examples/` directory for complete configuration file examples.

## Performance & Scalability

### Multiprocessing Architecture

net-traffic-sim uses Python's multiprocessing to generate traffic in parallel:
- **Auto worker selection**: Automatically detects CPU cores and creates optimal worker count
- **Protocol isolation**: Each protocol runs in a separate process to maximize throughput
- **Buffered writes**: `FastPacketSerializer` buffers writes to minimize disk I/O overhead

### Performance Benchmarks

Test results on modern hardware (Apple M1/M2, 8-12 cores):

**Test Suite Performance (186 tests):**
- Sequential execution: ~150s
- 2 workers: ~77s (1.9x speedup)
- 4 workers: ~52s (2.9x speedup)
- Auto (12 workers): ~42s (3.6x speedup)

**PCAP Generation Performance:**
- Small capture (50 MB, 10 min): ~15-30 seconds
- Medium capture (500 MB, 12 hours): ~2-4 minutes
- Large capture (1500 MB, 24 hours): ~5-10 minutes
- Multi-day capture (3000 MB, 72 hours): ~15-25 minutes

**Note:** Performance varies based on:
- CPU core count (more cores = faster)
- Disk I/O speed (SSD strongly recommended)
- Checksum generation (`--checksums` adds ~30% overhead)
- Protocol mix and traffic density

### Resource Requirements

**Disk Space:**
- Temporary: ~2x target PCAP size during generation
- Final: 1x target PCAP size after merge

**Memory:**
- Typical: 500 MB - 2 GB depending on worker count
- Large captures: Up to 4 GB with many parallel workers

**CPU:**
- Minimum: 2 cores
- Recommended: 4+ cores for optimal performance
- Ideal: 8+ cores for maximum throughput

For architectural details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Security Considerations

⚠️ **Important**: This tool generates realistic network traffic, including simulated attack patterns.

### Legal and Ethical Use

- **Only use in isolated test environments** (home labs, CTF infrastructure, authorized testing networks)
- **Never run against production networks** without explicit written authorization
- Generated scanner/attacker traffic may trigger IDS/IPS systems and security alerts
- Be aware of legal implications in your jurisdiction regarding traffic generation and security testing

### This Tool is Designed For:

✅ Security training and education
✅ CTF challenge creation
✅ Network monitoring system testing (SIEM, IDS/IPS)
✅ Blue team defensive exercises
✅ Research purposes in controlled environments
✅ Protocol analysis and forensics training

### This Tool is NOT For:

❌ Unauthorized network testing
❌ Production network traffic generation
❌ Malicious scanning or reconnaissance
❌ Circumventing security controls
❌ Any illegal or unethical activities

### Attack Traffic Included

The simulator includes realistic attack simulation traffic:
- Port scanning and service enumeration
- LDAP reconnaissance
- Exploit attempts (simulated, non-functional)
- Brute force authentication attempts (simulated)

This traffic is intended for **defensive training only**. Ensure your test environment is properly isolated.

## Developer Guide

### Adding New Protocols

To add a new protocol to the simulator:

1. **Create protocol file**: `src/net_traffic_sim/protocols/your_protocol.py`

2. **Implement protocol class** extending `BaseProtocol`:
   ```python
   from net_traffic_sim.protocols.base import BaseProtocol

   class YourProtocol(BaseProtocol):
       def generate(self, serializer, start_time, duration_seconds):
           # Implementation here
           pass
   ```

3. **Register in PROTOCOL_REGISTRY**: Edit `src/net_traffic_sim/protocols/__init__.py`

4. **Add comprehensive tests**: Create `tests/test_your_protocol.py`

5. **Update documentation**:
   - Add to README.md protocol table
   - Update test count in README.md
   - Add architectural notes to ARCHITECTURE.md if needed

For detailed API documentation, see the [BaseProtocol API](#baseprotocol-abstract-class) section below.

### BaseProtocol Abstract Class

The `BaseProtocol` class (`src/net_traffic_sim/protocols/base.py`) provides a foundation for building custom protocol simulators:

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

        # Add protocol-specific logic
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

### Code Style

This project uses:
- **Ruff** for linting and formatting
- **Type hints** for all functions (Python 3.10+ syntax)
- **Docstrings** for public APIs
- **Conventional Commits** for commit messages

Before submitting changes:
```bash
# Lint check
ruff check .

# Auto-fix issues
ruff check . --fix

# Format code
ruff format .
```

Configuration is defined in `pyproject.toml`.

## Testing

The project uses pytest with parallel test execution via pytest-xdist for faster test runs.

### Running Tests

```bash
# Standard parallel test execution (recommended)
pytest -n auto

# Run tests with specific number of workers
pytest -n 4

# Run tests sequentially (slower)
pytest

# Run specific protocol tests
pytest tests/test_radius.py -v
pytest tests/test_ntp.py -v

# Run with coverage report
pytest --cov=src/net_traffic_sim --cov-report=html
```

### Test Coverage

- **186 comprehensive tests** covering all 35 protocols
- **NTP**: 14 dedicated tests for time synchronization flows
- **RADIUS**: 24 dedicated tests for enterprise authentication flows
- **Core protocols**: 148 tests for baseline network traffic
- All tests passing with parallel execution support

### Performance Benchmarks (186 tests)

- Sequential execution: ~150s
- 2 workers: ~77s (1.9x speedup)
- 4 workers: ~52s (2.9x speedup)
- Auto (12 workers): ~42s (3.6x speedup)

## Troubleshooting

### Common Issues

**`mergecap: command not found`**
- **Solution**: Install Wireshark tools
  - macOS: `brew install wireshark`
  - Ubuntu/Debian: `sudo apt install wireshark-common`
  - Windows: Install Wireshark and add to PATH

**Permission errors with Scapy**
- **Cause**: Raw socket creation requires elevated privileges
- **Solution**:
  - Linux/macOS: Run with `sudo` or configure capabilities
  - Windows: Run terminal as Administrator
  - Alternative: Use PCAP files for testing instead of live capture

**Out of disk space during generation**
- **Cause**: Temporary PCAPs require ~2x target size
- **Solution**:
  - Free up disk space
  - Use smaller `--target-size`
  - Change `--output-dir` to volume with more space

**Slow generation times**
- **Check**: CPU core count with `python -c "import os; print(os.cpu_count())"`
- **Solution**:
  - Use `--estimate-only` to check expected runtime
  - Reduce `--duration` or `--target-size`
  - Ensure SSD is being used (not HDD)
  - Use `--smoke` mode for quick testing

**"Bad checksum" warnings in Wireshark**
- **Cause**: Default mode uses `--no-checksums` for speed
- **Solution**: Use `--checksums` flag for validated packets (slower)
- **Note**: Bad checksums don't affect traffic analysis in most cases

**Import errors after installation**
- **Solution**: Ensure virtual environment is activated
  ```bash
  source .venv/bin/activate  # macOS/Linux
  .\.venv\Scripts\Activate.ps1  # Windows
  ```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:
- Code style requirements (Ruff, type hints)
- Testing requirements (pytest, coverage)
- Pull request process
- Commit message conventions

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Internal architecture, design decisions, multiprocessing coordination
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines and development workflow
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and notable changes
- **[examples/](examples/)** - Configuration file examples for common scenarios

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Version**: 0.1.0
**Maintained by**: moex01
**Repository**: https://github.com/moex01/net-traffic-sim
