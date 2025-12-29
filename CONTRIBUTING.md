# Contributing to net-traffic-sim

Thank you for your interest in contributing to net-traffic-sim! This document provides guidelines for contributing to the project.

## Table of Contents
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Adding a New Protocol](#adding-a-new-protocol)
- [Pull Request Process](#pull-request-process)
- [Commit Message Guidelines](#commit-message-guidelines)

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/net-traffic-sim.git
   cd net-traffic-sim
   ```
3. **Create a feature branch:**
   ```bash
   git checkout -b feat/your-feature-name
   ```

## Development Setup

### Prerequisites
- Python 3.10 or higher
- Wireshark tools (tshark, mergecap)

### Installation

1. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install the package in editable mode:**
   ```bash
   pip install -e .
   ```

3. **Verify installation:**
   ```bash
   net-traffic-sim --help
   pytest --version
   ruff --version
   ```

## Code Style

This project follows strict code quality standards enforced by [Ruff](https://docs.astral.sh/ruff/).

### Configuration

The project uses the following Ruff configuration (from `pyproject.toml`):
- **Line length**: 160 characters
- **Target Python**: 3.10+
- **Enabled rules**: pycodestyle (E), pyflakes (F), isort (I), flake8-bugbear (B), pyupgrade (UP)

### Linting and Formatting

```bash
# Check for linting issues
ruff check .

# Auto-fix issues
ruff check . --fix

# Format code
ruff format .
```

### Type Hints

All functions must include type hints using Python 3.10+ syntax:

```python
def generate_packet(
    protocol: str,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.1"
) -> bytes:
    """Generate a single packet for the specified protocol."""
    ...
```

### Docstrings

Public APIs must have docstrings following this format:

```python
def generate_flow(protocol: str, count: int) -> list[bytes]:
    """Generate a realistic traffic flow.

    Args:
        protocol: Protocol name (e.g., "http", "dns")
        count: Number of packets to generate

    Returns:
        List of raw packet bytes
    """
    ...
```

### Pre-commit Checklist

Before committing, ensure:

```bash
# Lint check (must pass)
ruff check .

# Format code
ruff format .

# Run all tests (must pass)
pytest -v

# Check test coverage (aim for >80%)
pytest --cov=src/net_traffic_sim --cov-report=term
```

## Testing Requirements

All contributions must include tests.

### Test Coverage Standards

- **New protocols**: Minimum 80% coverage with comprehensive test cases
- **Bug fixes**: Regression test demonstrating the fix
- **New features**: Cover all new code paths

### Running Tests

```bash
# Run all tests
pytest -v

# Run all tests in parallel (faster, recommended)
pytest -n auto

# Run specific test file
pytest tests/test_your_protocol.py -v

# Run with coverage report
pytest --cov=src/net_traffic_sim --cov-report=html
open htmlcov/index.html  # View coverage report
```

### Writing Tests

Test files should follow this structure:

```python
"""Tests for YourProtocol protocol implementation."""

import time
from io import BytesIO

import pytest
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from net_traffic_sim.protocols.your_protocol import (
    generate_your_protocol_packet,
    generate_your_protocol_flow,
)
from net_traffic_sim.serializer import FastPacketSerializer


class TestYourProtocolPacketGeneration:
    """Test packet generation for YourProtocol."""

    def test_basic_packet_generation(self):
        """Test basic packet generation succeeds."""
        packets = generate_your_protocol_packet("10.1.1.100", "10.1.1.1", time.time())

        assert len(packets) > 0, "Should generate at least one packet"
        assert IP in packets[0]
        assert packets[0][IP].src == "10.1.1.100"

    def test_with_serializer(self):
        """Test packet generation with FastPacketSerializer."""
        buffer = BytesIO()
        with FastPacketSerializer(buffer, buffer_size=10) as serializer:
            packets = generate_your_protocol_packet(
                "10.1.1.100",
                "10.1.1.1",
                time.time(),
                serializer=serializer
            )

            assert len(packets) == 0, "Should return empty list with serializer"
            assert serializer.packet_count > 0, "Serializer should have packets"
```

## Adding a New Protocol

Follow this workflow to add a new protocol:

### 1. Create Protocol File

Create `src/net_traffic_sim/protocols/your_protocol.py`:

```python
"""YourProtocol protocol simulation.

Brief description of what this protocol does and its use case.

RFC XXXX (if applicable)
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet
    from ..serializer import FastPacketSerializer

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from ..logging_setup import get_logger
from .base import _emit_packet, _udp_packet

logger = get_logger(__name__)

# Protocol constants
YOUR_PROTOCOL_PORT = 1234


def generate_your_protocol_packet(
    src_ip: str,
    dst_ip: str,
    start_time: float,
    serializer: FastPacketSerializer | None = None,
) -> list[Packet]:
    """Generate a YourProtocol packet.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        start_time: Timestamp for packet
        serializer: Optional packet serializer

    Returns:
        List of packets (or empty list if using serializer)
    """
    packets: list[Packet] = []
    sport = random.randint(1024, 65535)

    # Build your protocol packet
    payload = b"your protocol data"
    pkt = _udp_packet(src_ip, dst_ip, sport, YOUR_PROTOCOL_PORT, payload, start_time)
    _emit_packet(serializer, packets, pkt, start_time)

    return packets if serializer is None else []


__all__ = [
    "YOUR_PROTOCOL_PORT",
    "generate_your_protocol_packet",
]
```

### 2. Register Protocol

Add to `src/net_traffic_sim/protocols/__init__.py`:

```python
from . import your_protocol  # noqa: F401

# Update PROTOCOL_REGISTRY if needed
```

### 3. Create Tests

Create `tests/test_your_protocol.py` with comprehensive tests (see Testing Requirements above).

### 4. Update Documentation

Update these files:

**README.md:**
- Add protocol to Supported Protocols table with RFC/standard
- Update total protocol count
- Update test count

**CHANGELOG.md:**
- Add entry under `[Unreleased]` section

**ARCHITECTURE.md (if needed):**
- Add protocol details if it introduces new patterns

### 5. Verify

```bash
# Run new tests
pytest tests/test_your_protocol.py -v

# Run all tests
pytest -n auto

# Check coverage
pytest --cov=src/net_traffic_sim/protocols/your_protocol --cov-report=term

# Lint check
ruff check .
```

## Pull Request Process

1. **Ensure all tests pass:**
   ```bash
   pytest -n auto
   ruff check .
   ```

2. **Update documentation** to reflect your changes

3. **Write clear commit messages** following conventional commits format

4. **Push to your fork:**
   ```bash
   git push origin feat/your-feature-name
   ```

5. **Open a Pull Request** on GitHub with:
   - Clear title following `<type>: <description>` format
   - Description of what changed and why
   - Reference to any related issues (e.g., "Fixes #123")
   - Screenshots/examples if applicable

6. **Address review feedback** promptly

7. **Ensure CI passes** - GitHub Actions will run tests and linting automatically

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

### Format

```
<type>: <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature (e.g., new protocol implementation)
- `fix`: Bug fix
- `docs`: Documentation changes only
- `test`: Test additions or changes
- `refactor`: Code refactoring without feature changes
- `perf`: Performance improvements
- `chore`: Maintenance tasks (dependencies, tooling, configuration)

### Examples

**New Feature:**
```
feat: Add MQTT protocol simulation

- Implement MQTT publish/subscribe flows
- Add 18 comprehensive tests for MQTT v3.1.1
- Support QoS levels 0, 1, and 2
- Update documentation with MQTT protocol details
```

**Bug Fix:**
```
fix: Resolve timing issue in NTP packet generation

The NTP timestamp calculation was using local time instead of UTC,
causing incorrect time values in generated packets. Changed to use
time.gmtime() for proper UTC handling.

Fixes #123
```

**Documentation:**
```
docs: Clarify configuration file format in README

- Add examples for both JSON and YAML formats
- Explain configuration precedence order
- Update Quick Start with mergecap command
```

**Refactoring:**
```
refactor: Remove duplicate utility functions from sharepoint.py

- Consolidate helper functions into base.py
- Eliminate 593 lines of duplicate code
- All tests still passing
```

### Good Practices

- Use imperative mood ("Add feature" not "Added feature")
- Keep first line under 72 characters
- Provide context in the body for non-trivial changes
- Reference issues/PRs when applicable (e.g., "Fixes #42", "Closes #123")
- Break unrelated changes into separate commits

## Questions or Help?

- **Bug reports**: [Open an issue](https://github.com/moex01/net-traffic-sim/issues/new) with:
  - Clear description of the bug
  - Steps to reproduce
  - Expected vs actual behavior
  - Environment details (OS, Python version)

- **Feature requests**: [Open an issue](https://github.com/moex01/net-traffic-sim/issues/new) describing:
  - The use case or problem to solve
  - Proposed solution or approach
  - Any alternatives considered

- **Questions**: Check [existing issues](https://github.com/moex01/net-traffic-sim/issues) or open a new one

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Assume good intentions
- Help create a welcoming environment for all contributors

---

Thank you for contributing to net-traffic-sim! 🚀
