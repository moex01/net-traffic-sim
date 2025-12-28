"""Centralized configuration for the PCAP generator.

These constants define the synthetic environment, traffic rates, and
content catalogs used across protocol generators. Adjust values here to
change the scenario without editing generator logic.
"""

import json
import logging
import os
from dataclasses import dataclass, replace
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from . import defaults

logger = logging.getLogger(__name__)

# Try to import yaml for YAML config support
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# Dynamic Configuration Loading
# ---------------------------------------------------------------------------

# 1. Load defaults into the module namespace.
#    This ensures that 'from net_traffic_sim.config import WEB_APP_SERVER_IP' works.
for _key in dir(defaults):
    if _key.isupper():
        globals()[_key] = getattr(defaults, _key)

# 2. Override with values from external config file (if present).
#    Priority: ENV VAR > config.json in CWD
_config_path = os.environ.get("NET_TRAFFIC_SIM_CONFIG", "config.json")
if os.path.exists(_config_path):
    try:
        with open(_config_path) as _f:
            _data = json.load(_f)
            for _key, _value in _data.items():
                # Only update known configuration keys (security/safety check)
                if _key in globals() and _key.isupper():
                    globals()[_key] = _value
    except Exception as _e:
        logger.warning("Failed to load configuration from %s: %s", _config_path, _e)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Default capture window (8 AM local time, 24 hours).
@lru_cache(maxsize=1)
def default_start_time() -> float:
    """Return the default start timestamp (8 AM local time, today)."""
    start_datetime = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)
    return start_datetime.timestamp()


# ---------------------------------------------------------------------------
# Config Object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    # We use the module-level globals as defaults here.
    # Note: These defaults are bound at class definition time.
    # If config.json is loaded, these will reflect the file's values.
    sql_queries_per_sec: int = globals().get("SQL_QUERIES_PER_SEC", 1)
    http_requests_per_sec: int = globals().get("HTTP_REQUESTS_PER_SEC", 30)
    dns_queries_per_sec: int = globals().get("DNS_QUERIES_PER_SEC", 20)
    smb_simulated_size_mb: int = globals().get("DEFAULT_SMB_SIMULATED_SIZE_MB", 20)
    seed: int | None = globals().get("RANDOM_SEED", None)

    @classmethod
    def from_defaults(cls) -> "Config":
        return cls()

    def with_overrides(self, **kwargs) -> "Config":
        return replace(self, **kwargs)


# ---------------------------------------------------------------------------
# Protocol Configuration from YAML
# ---------------------------------------------------------------------------


def load_protocol_config_from_yaml(yaml_path: str | Path) -> dict[str, dict]:
    """Load protocol configuration from a YAML file.

    Args:
        yaml_path: Path to YAML configuration file

    Returns:
        Dictionary mapping protocol names to their configuration dictionaries

    Raises:
        FileNotFoundError: If YAML file doesn't exist
        ImportError: If PyYAML is not installed
        ValueError: If YAML file is invalid

    Example YAML format:
        protocols:
          dns:
            enabled: true
            packet_count: 50
          http:
            enabled: true
            packet_count: 100
          smb:
            enabled: false
    """
    if not HAS_YAML:
        raise ImportError("PyYAML is required to load YAML configurations. Install with: pip install pyyaml")

    yaml_path = Path(yaml_path)
    if not yaml_path.exists():
        raise FileNotFoundError(f"YAML configuration file not found: {yaml_path}")

    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        if not data or "protocols" not in data:
            logger.warning("YAML file %s missing 'protocols' section", yaml_path)
            return {}

        protocols = data["protocols"]
        if not isinstance(protocols, dict):
            raise ValueError("'protocols' section must be a dictionary")

        # Parse and validate protocol configurations
        protocol_configs = {}
        for protocol_name, config in protocols.items():
            if not isinstance(config, dict):
                logger.warning("Skipping invalid protocol config for '%s': not a dictionary", protocol_name)
                continue

            # Extract packet_count with default of 0
            packet_count = config.get("packet_count", 0)
            if not isinstance(packet_count, int) or packet_count < 0:
                logger.warning(
                    "Invalid packet_count for protocol '%s': %s (using default 0)",
                    protocol_name,
                    packet_count,
                )
                packet_count = 0

            protocol_configs[protocol_name] = {
                "enabled": config.get("enabled", True),
                "packet_count": packet_count,
                "custom_params": config.get("params", None),
            }

        return protocol_configs

    except yaml.YAMLError as e:
        raise ValueError(f"Failed to parse YAML file {yaml_path}: {e}") from e
    except Exception as e:
        logger.warning("Error loading protocol config from %s: %s", yaml_path, e)
        raise


def get_protocol_packet_count(protocol_name: str, yaml_config: dict[str, dict] | None = None) -> int:
    """Get the packet count for a specific protocol from configuration.

    Args:
        protocol_name: Name of the protocol (e.g., 'dns', 'http')
        yaml_config: Optional protocol configuration dict from load_protocol_config_from_yaml()

    Returns:
        Packet count for the protocol (0 means use CLI default)
    """
    if yaml_config and protocol_name in yaml_config:
        return yaml_config[protocol_name].get("packet_count", 0)
    return 0
