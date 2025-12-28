"""Tests for the dynamic configuration loading system."""

import json
import os

from net_traffic_sim import defaults
from net_traffic_sim.config import Config


def test_config_defaults():
    """Verify that the Config object defaults match the hardcoded defaults."""
    config = Config.from_defaults()
    assert config.sql_queries_per_sec == defaults.SQL_QUERIES_PER_SEC
    assert config.http_requests_per_sec == defaults.HTTP_REQUESTS_PER_SEC
    assert config.dns_queries_per_sec == defaults.DNS_QUERIES_PER_SEC
    assert config.smb_simulated_size_mb == defaults.DEFAULT_SMB_SIMULATED_SIZE_MB
    assert config.seed == defaults.RANDOM_SEED


def test_config_override_from_json(tmp_path):
    """Verify that values can be loaded from a JSON file."""
    # Create a custom config file
    custom_config = {"SQL_QUERIES_PER_SEC": 999, "HTTP_REQUESTS_PER_SEC": 888, "RANDOM_SEED": 12345}
    config_file = tmp_path / "custom_config.json"
    with open(config_file, "w") as f:
        json.dump(custom_config, f)

    # Mock the environment variable to point to our custom file
    # We also need to reload the config module to trigger the file reading logic
    # allowing us to test the dynamic loading. However, reloading modules in tests
    # is messy.
    #
    # A cleaner way given the current implementation (which runs code on import)
    # is to verify the *mechanism* via subprocess or by mocking the internal logic if accessible.
    #
    # Since the config loading happens at module level, we'll use a subprocess to
    # verify end-to-end behavior without polluting the test runner's namespace.

    import subprocess
    import sys

    script = """
import os
import json
from net_traffic_sim.config import Config

# Verify loaded values
config = Config.from_defaults()
print(json.dumps({
    "sql": config.sql_queries_per_sec,
    "http": config.http_requests_per_sec,
    "seed": config.seed
}))
"""
    env = os.environ.copy()
    env["NET_TRAFFIC_SIM_CONFIG"] = str(config_file)

    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, check=True)

    data = json.loads(result.stdout)
    assert data["sql"] == 999
    assert data["http"] == 888
    assert data["seed"] == 12345
