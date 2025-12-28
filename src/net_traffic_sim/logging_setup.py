"""Logging configuration for net-traffic-sim."""

from __future__ import annotations

import logging
import os


def configure_logging(verbose: bool) -> None:
    """Configure root logging for CLI usage."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")
    os.environ["NET_TRAFFIC_SIM_LOG_LEVEL"] = "DEBUG" if verbose else "INFO"
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy").setLevel(logging.ERROR)


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a module logger under the net-traffic-sim namespace."""
    if not logging.getLogger().handlers:
        level_name = os.environ.get("NET_TRAFFIC_SIM_LOG_LEVEL", "INFO")
        level = logging.DEBUG if level_name == "DEBUG" else logging.INFO
        logging.basicConfig(level=level, format="%(message)s")
    return logging.getLogger(name or "net_traffic_sim")
