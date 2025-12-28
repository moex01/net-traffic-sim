"""Pre-generated random value pools for performance-critical paths."""

from __future__ import annotations

import random

from .logging_setup import get_logger

logger = get_logger(__name__)


class RandomPool:
    """Pre-generated random values pool for performance-critical generation."""

    def __init__(self, size: int = 100000, seed: int | None = None, verbose: bool = False) -> None:
        self.size = size
        self._indices: dict[str, int] = {}
        self.rng = random.Random(seed)
        if verbose:
            logger.info(f"[*] Pre-generating {size:,} random values for performance...")

        # Pre-generate all random values at startup
        self.ints_1_65535 = [self.rng.randint(1, 65535) for _ in range(size)]
        self.ints_1024_65535 = [self.rng.randint(1024, 65535) for _ in range(size)]  # Common port range
        self.ints_0_2_32 = [self.rng.getrandbits(32) for _ in range(size)]
        self.ints_100_1000 = [self.rng.randint(100, 1000) for _ in range(size)]
        self.floats_0_1 = [self.rng.random() for _ in range(size)]

        # Timing delays (common patterns in network traffic)
        self.uniform_005_015 = [self.rng.uniform(0.005, 0.015) for _ in range(size)]
        self.uniform_001_005 = [self.rng.uniform(0.001, 0.005) for _ in range(size)]
        self.uniform_001_003 = [self.rng.uniform(0.001, 0.003) for _ in range(size)]
        self.uniform_001_002 = [self.rng.uniform(0.001, 0.002) for _ in range(size)]
        self.uniform_0001_001 = [self.rng.uniform(0.0001, 0.001) for _ in range(size)]

        # DNS-specific delays (0.002-0.5)
        self.uniform_002_05 = [self.rng.uniform(0.002, 0.5) for _ in range(size)]  # DNS query gaps

        # HTTP-specific delays (1-5 seconds)
        self.uniform_1_5 = [self.rng.uniform(1, 5) for _ in range(size)]  # HTTP session gaps

        # SMB-specific delays (2-10 seconds)
        self.uniform_2_10 = [self.rng.uniform(2, 10) for _ in range(size)]  # SMB/HTTPS session gaps

        # Large delays (5-25 seconds for attacker recon)
        self.uniform_5_25 = [self.rng.uniform(5, 25) for _ in range(size)]  # Attacker timing

        # Exponential-like delays (1-10 seconds)
        self.uniform_1_10 = [self.rng.uniform(1, 10) for _ in range(size)]  # Generic session delays

        # External ping delays (20-50ms)
        self.uniform_020_050 = [self.rng.uniform(0.020, 0.050) for _ in range(size)]  # External latency

        # Internal ping delays (0.5-3ms)
        self.uniform_0005_003 = [self.rng.uniform(0.0005, 0.003) for _ in range(size)]  # Internal latency

        # TTL values
        self.ttls = [self.rng.choice([64, 128]) for _ in range(size)]

        # Per-destination IP ID counters (realistic OS behavior)
        self.ip_id_counters = {}  # {(src_ip, dst_ip): current_id}

        if verbose:
            ram_used = (size * 8 * 18) / (1024 * 1024)  # 18 arrays now
            logger.info(f"[OK] Random pool ready (uses ~{ram_used:.1f} MB RAM)")

    def _next(self, pool_name: str, pool: list) -> int | float:
        """Get next value from a named pool with independent wraparound."""
        idx = self._indices.get(pool_name, 0)
        val = pool[idx % self.size]
        idx += 1
        if idx >= self.size * 10:  # Reset after 10 full cycles
            idx = 0
        self._indices[pool_name] = idx
        return val

    # Fast accessors for common random patterns
    def ip_id(self, src_ip=None, dst_ip=None):
        """
        Generate IP ID with per-destination counter (realistic OS behavior).
        Modern OSes use per-destination counters, not global sequential IDs.
        """
        if src_ip is None or dst_ip is None:
            # Fallback for packets without source/dest info
            return self._next("ints_1_65535", self.ints_1_65535)

        # Create flow key
        flow_key = (src_ip, dst_ip)

        # Initialize counter if not exists (random starting point)
        if flow_key not in self.ip_id_counters:
            self.ip_id_counters[flow_key] = self.rng.randint(1000, 60000)

        # Increment counter (with wraparound at 65535)
        current_id = self.ip_id_counters[flow_key]
        self.ip_id_counters[flow_key] = (current_id + 1) % 65536

        # Add small jitter (+/-3) to prevent perfect sequential IDs
        jitter = self.rng.randint(-3, 3)
        return max(1, min(65535, current_id + jitter))

    def dns_txid(self):
        """Random DNS transaction ID (16-bit)."""
        return self._next("ints_1_65535", self.ints_1_65535)

    # Commonly used random methods - all O(1)
    def port(self):
        """Random port 1024-65535 - O(1)"""
        return self._next("ints_1024_65535", self.ints_1024_65535)

    def seq_num(self):
        """Random TCP sequence number - O(1)"""
        return self._next("ints_0_2_32", self.ints_0_2_32)

    def small_int(self):
        """Random integer 100-1000 - O(1)"""
        return self._next("ints_100_1000", self.ints_100_1000)

    def chance(self):
        """Random float 0-1 for probability - O(1)"""
        return self._next("floats_0_1", self.floats_0_1)

    def ttl(self):
        """Random TTL 64 or 128 - O(1)"""
        return self._next("ttls", self.ttls)

    # Timing delays - all O(1)
    def delay_handshake(self):
        """Handshake delay (5-15ms) - O(1)"""
        return self._next("uniform_005_015", self.uniform_005_015)

    def delay_medium(self):
        """Medium delay (1-5ms) - O(1)"""
        return self._next("uniform_001_005", self.uniform_001_005)

    def delay_small(self):
        """Small delay (1-3ms) - O(1)"""
        return self._next("uniform_001_003", self.uniform_001_003)

    def delay_tiny(self):
        """Tiny delay (1-2ms) - O(1)"""
        return self._next("uniform_001_002", self.uniform_001_002)

    def delay_minimal(self):
        """Minimal delay (0.1-1ms) - O(1)"""
        return self._next("uniform_0001_001", self.uniform_0001_001)

    def delay_dns(self):
        """DNS query gap (2-500ms) - O(1)"""
        return self._next("uniform_002_05", self.uniform_002_05)

    def delay_http(self):
        """HTTP session gap (1-5 seconds) - O(1)"""
        return self._next("uniform_1_5", self.uniform_1_5)

    def delay_smb(self):
        """SMB/HTTPS session gap (2-10 seconds) - O(1)"""
        return self._next("uniform_2_10", self.uniform_2_10)

    def delay_attacker(self):
        """Attacker recon timing (5-25 seconds) - O(1)"""
        return self._next("uniform_5_25", self.uniform_5_25)

    def delay_session(self):
        """Generic session delay (1-10 seconds) - O(1)"""
        return self._next("uniform_1_10", self.uniform_1_10)

    def latency_external(self):
        """External ping latency (20-50ms) - O(1)"""
        return self._next("uniform_020_050", self.uniform_020_050)

    def latency_internal(self):
        """Internal ping latency (0.5-3ms) - O(1)"""
        return self._next("uniform_0005_003", self.uniform_0005_003)
