"""net_traffic_sim package."""

import logging

# Add NullHandler to prevent "No handler found" warnings when used as a library
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__: list[str] = []
