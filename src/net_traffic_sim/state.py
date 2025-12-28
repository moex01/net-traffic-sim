"""Shared state and connection tracking for packet generation."""

import random
from collections import OrderedDict

from .config import (
    ADMIN_WORKSTATION_IPS,
    ATTACKER_PUBLIC_IPS,
    DOMAIN_CONTROLLER_IP,
    EPHEMERAL_PORT_RANGE,
    EXTERNAL_HOST_IPS,
    FILE_SHARE_SERVER_IP,
    FTP_SERVER_IP,
    GATEWAY_IP,
    GATEWAY_MAC_ADDRESS,
    HTTP_KEEPALIVE_CLOSE_PROBABILITY,
    HTTP_KEEPALIVE_EARLY_CLOSE_PROBABILITY,
    HTTP_KEEPALIVE_MAX_REQUESTS,
    HTTP_KEEPALIVE_TIMEOUT_SECONDS,
    LINUX_SERVER_IP,
    MAC_VENDOR_OUIS,
    MAIL_SERVER_IP,
    MONITORING_SERVER_IP,
    SHAREPOINT_SERVER_IP,
    SQL_SERVER_IP,
    SYSLOG_SERVER_IP,
    TCP_WINDOW_SQL_CLIENT,
    USER_WORKSTATION_IPS,
    VOIP_PBX_IP,
    VOIP_PHONE_IPS,
    WEB_APP_SERVER_IP,
    WSUS_SERVER_IP,
    Config,
    default_start_time,
)
from .helpers import (
    generate_etag,
    generate_realistic_user_agent,
    generate_server_versions,
    generate_session_cookie,
    init_sharepoint_ids,
    set_context_rng,
)
from .random_pool import RandomPool


class ConnectionState:
    """Track TCP connection state"""

    def __init__(self, src_ip, dst_ip, sport, dport, random_pool):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.seq = random_pool.seq_num()
        self.ack = 0
        self.window = random.choice(TCP_WINDOW_SQL_CLIENT) if dport == 1433 else 65535
        self.established = False

    def increment_seq(self, length):
        """Increment sequence number by payload length"""
        self.seq += length

    def set_ack(self, ack):
        """Set acknowledgment number"""
        self.ack = ack


class TrafficGenerator:
    """Main traffic generator with shared state"""

    def __init__(self, random_pool):
        self.random_pool = random_pool
        self.current_time = default_start_time()
        self.connections = {}  # Track all TCP connections
        self.dns_cache = {}  # DNS caching
        self.port_allocator = {}  # Track ephemeral ports per host
        self.mac_table = self.generate_mac_table()
        self.session_cookies = {}  # Track session cookie per source IP
        self.user_agents = {}
        self.server_versions = {}
        self.resource_cache = {}
        self.http_connection_pool = {}
        self.dhcp_renewal_events = {}

    def generate_mac_table(self):
        """Generate realistic MAC addresses from real vendors"""
        macs = {}
        used_macs = set()

        def random_mac_for_device(device_type):
            """Generate MAC based on device type"""
            if device_type == "server":
                vendor_pool = MAC_VENDOR_OUIS["server"]
            elif device_type == "workstation":
                vendor_pool = MAC_VENDOR_OUIS["workstation"]
            elif device_type == "router":  # Routers use Cisco OUIs.
                vendor_pool = MAC_VENDOR_OUIS["router"]
            elif device_type == "external":
                vendor_pool = MAC_VENDOR_OUIS["external"]
            else:
                vendor_pool = MAC_VENDOR_OUIS["vm"]

            max_attempts = 10000
            for _ in range(max_attempts):
                oui = random.choice(vendor_pool)
                mac = f"{oui}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
                if mac not in used_macs:
                    used_macs.add(mac)
                    return mac
            # Fallback: generate a fully random MAC if all OUI combinations exhausted
            fallback_mac = f"02:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
            used_macs.add(fallback_mac)
            return fallback_mac

        # Gateway uses the configured MAC address for consistency.
        macs[GATEWAY_IP] = GATEWAY_MAC_ADDRESS

        # Servers get Dell/HP MACs
        macs[WEB_APP_SERVER_IP] = random_mac_for_device("server")
        macs[SQL_SERVER_IP] = random_mac_for_device("server")
        macs[DOMAIN_CONTROLLER_IP] = random_mac_for_device("server")
        macs[FILE_SHARE_SERVER_IP] = random_mac_for_device("server")
        macs[MAIL_SERVER_IP] = random_mac_for_device("server")
        macs[MONITORING_SERVER_IP] = random_mac_for_device("server")
        macs[SYSLOG_SERVER_IP] = random_mac_for_device("server")
        macs[WSUS_SERVER_IP] = random_mac_for_device("server")
        macs[LINUX_SERVER_IP] = random_mac_for_device("server")
        macs[FTP_SERVER_IP] = random_mac_for_device("server")
        macs[VOIP_PBX_IP] = random_mac_for_device("server")
        macs[SHAREPOINT_SERVER_IP] = random_mac_for_device("server")

        # Workstations get Intel MACs
        for ip in USER_WORKSTATION_IPS + ADMIN_WORKSTATION_IPS:
            macs[ip] = random_mac_for_device("workstation")

        for ip in VOIP_PHONE_IPS:
            macs[ip] = random_mac_for_device("workstation")

        # External IPs get random vendor
        for ip in EXTERNAL_HOST_IPS + ATTACKER_PUBLIC_IPS:
            macs[ip] = random_mac_for_device("external")

        return macs

    def allocate_port(self, host, max_attempts=1000):
        """Allocate realistic ephemeral port (randomized within range)"""
        if host not in self.port_allocator:
            # Use OrderedDict for O(1) lookup and LRU-style eviction
            self.port_allocator[host] = OrderedDict()

        # Randomize within ephemeral range instead of sequential
        min_port, max_port = EPHEMERAL_PORT_RANGE
        for _ in range(max_attempts):
            port = random.randint(min_port, max_port)
            if port not in self.port_allocator[host]:
                self.port_allocator[host][port] = True
                # Prevent memory leak: limit tracking to last 5000 ports
                if len(self.port_allocator[host]) > 5000:
                    # Remove oldest 1000 ports (LRU eviction)
                    for _ in range(1000):
                        self.port_allocator[host].popitem(last=False)
                return port
        raise RuntimeError(f"Failed to allocate ephemeral port for {host} after {max_attempts} attempts. Port range {min_port}-{max_port} may be exhausted.")

    def get_connection(self, src_ip, dst_ip, sport, dport):
        """Get or create TCP connection state with LRU eviction"""
        key = (src_ip, dst_ip, sport, dport)
        if key not in self.connections:
            # Evict old connections if we exceed 10,000 tracked
            if len(self.connections) > 10000:
                # Remove oldest 2000 connections
                keys_to_remove = list(self.connections.keys())[:2000]
                for k in keys_to_remove:
                    del self.connections[k]

            self.connections[key] = ConnectionState(src_ip, dst_ip, sport, dport, self.random_pool)
        return self.connections[key]

    def get_session_cookie(self, src_ip):
        """
        Get or create a session cookie for a source IP (session persistence).
        Real browsers reuse a stable session cookie across multiple requests.
        """
        if src_ip not in self.session_cookies:
            self.session_cookies[src_ip] = generate_session_cookie()
        return self.session_cookies[src_ip]

    def get_user_agent(self, src_ip):
        """
        Get or create User-Agent for a source IP.
        Real users don't change browsers between requests.
        """
        if src_ip not in self.user_agents:
            self.user_agents[src_ip] = generate_realistic_user_agent()
        return self.user_agents[src_ip]

    def get_server_versions(self, server_ip):
        """
        Get or create server version info for a server IP.
        Real servers don't change IIS/ASP.NET versions between responses.
        """
        if server_ip not in self.server_versions:
            self.server_versions[server_ip] = generate_server_versions()
        return self.server_versions[server_ip]

    def should_return_304(self, src_ip, uri, current_timestamp):
        """
        Determine if this resource should return 304 Not Modified.
        Real browsers cache resources and send If-None-Match/If-Modified-Since.

        Returns: (should_304, etag, last_modified, is_cached)
        """
        cache_key = (src_ip, uri)

        # First time seeing this resource
        if cache_key not in self.resource_cache:
            etag = generate_etag()
            # Resource was "created" sometime in the past (1-30 days ago)
            last_modified = current_timestamp - random.uniform(86400, 2592000)

            self.resource_cache[cache_key] = {"etag": etag, "last_modified": last_modified, "first_seen": current_timestamp}
            return False, etag, last_modified, False

        # Subsequent request for same resource
        cached = self.resource_cache[cache_key]
        time_since_first = current_timestamp - cached["first_seen"]

        # 30% chance of 304 if resource was accessed before
        # Higher chance for static resources (CSS, JS, images)
        if uri.endswith((".css", ".js", ".png", ".jpg", ".ico")):
            cache_hit_chance = 0.70  # 70% for static resources
        elif uri.startswith(("/static/", "/assets/", "/css/", "/js/")):
            cache_hit_chance = 0.55  # Static asset cache hits
        else:
            cache_hit_chance = 0.30  # 30% for dynamic content

        # Don't return 304 immediately (browser needs to request once)
        if time_since_first < 5:  # Less than 5 seconds since first request
            return False, cached["etag"], cached["last_modified"], True

        if random.random() < cache_hit_chance:
            return True, cached["etag"], cached["last_modified"], True
        else:
            return False, cached["etag"], cached["last_modified"], True

    def get_http_connection(self, src_ip, dst_ip, dport, current_timestamp):
        """
        Get existing HTTP connection or create new one.
        Real browsers keep connections alive and reuse them for multiple requests.

        Connection reuse rules:
        - Reuse if connection is < 120 seconds old and < 6 requests sent
        - 20% chance of closing connection early (user closes browser tab)
        - Always create new connection for first request

        Returns: (sport, is_new_connection, should_close_after)
        """
        pool_key = (src_ip, dst_ip, dport)

        # Check if we have an existing connection
        if pool_key in self.http_connection_pool:
            conn_info = self.http_connection_pool[pool_key]
            age = current_timestamp - conn_info["established"]
            requests_sent = conn_info["requests_sent"]

            # Reuse conditions
            if age < HTTP_KEEPALIVE_TIMEOUT_SECONDS and requests_sent < HTTP_KEEPALIVE_MAX_REQUESTS:
                # 20% chance of closing early (user behavior)
                if random.random() < HTTP_KEEPALIVE_EARLY_CLOSE_PROBABILITY:
                    # Close this connection and create new one
                    del self.http_connection_pool[pool_key]
                    sport = self.allocate_port(src_ip)
                    self.http_connection_pool[pool_key] = {"sport": sport, "established": current_timestamp, "requests_sent": 1}
                    return sport, True, False  # New connection
                else:
                    # Reuse existing connection
                    conn_info["requests_sent"] += 1

                    # Decide if we should close after this request (Connection: close)
                    # Close if this is the max request count OR random chance
                    should_close = requests_sent >= HTTP_KEEPALIVE_MAX_REQUESTS or (random.random() < HTTP_KEEPALIVE_CLOSE_PROBABILITY)

                    if should_close:
                        del self.http_connection_pool[pool_key]

                    return conn_info["sport"], False, should_close  # Reuse connection
            else:
                # Connection too old or too many requests - create new one
                del self.http_connection_pool[pool_key]

        # Create new connection
        sport = self.allocate_port(src_ip)
        self.http_connection_pool[pool_key] = {"sport": sport, "established": current_timestamp, "requests_sent": 1}

        return sport, True, False  # New connection


class GeneratorContext:
    """Context container for per-worker generator state."""

    def __init__(self, config: Config, seed: int | None = None, verbose: bool = False):
        self.config = config
        self.seed = config.seed if seed is None else seed
        if self.seed is not None:
            random.seed(self.seed)
        self.random_pool = RandomPool(size=100000, seed=self.seed, verbose=verbose)
        self.generator = TrafficGenerator(self.random_pool)
        self._mac_cache = {}

        set_context_rng(random if self.seed is None else random.Random(self.seed))
        init_sharepoint_ids()

    def get_mac_fast(self, ip):
        """Fast MAC lookup with caching (15% speedup for large captures)."""
        if ip not in self._mac_cache:
            self._mac_cache[ip] = self.generator.mac_table.get(ip, "00:00:00:00:00:01")
        return self._mac_cache[ip]

    def clear_mac_cache(self):
        """Clear MAC cache (call if MAC table is regenerated)."""
        self._mac_cache = {}


_DEFAULT_CONTEXT: GeneratorContext | None = None


def set_default_context(context: GeneratorContext) -> None:
    """Set the default context for this process."""
    global _DEFAULT_CONTEXT
    _DEFAULT_CONTEXT = context


def get_default_context(config: Config | None = None) -> GeneratorContext:
    """Get or create the default context for this process."""
    global _DEFAULT_CONTEXT
    if _DEFAULT_CONTEXT is None:
        _DEFAULT_CONTEXT = GeneratorContext(config or Config.from_defaults())
    elif config is not None and _DEFAULT_CONTEXT.config != config:
        _DEFAULT_CONTEXT = GeneratorContext(config)
    return _DEFAULT_CONTEXT


class _ContextProxy:
    """Lazy proxy that resolves to a context attribute on first use."""

    def __init__(self, attr: str) -> None:
        self._attr = attr

    def __getattr__(self, name):
        return getattr(getattr(get_default_context(), self._attr), name)

    def __repr__(self) -> str:
        return repr(getattr(get_default_context(), self._attr))


def get_mac_fast(ip):
    """Fast MAC lookup with caching (15% speedup for large captures)."""
    return get_default_context().get_mac_fast(ip)


def clear_mac_cache():
    """Clear MAC cache (call if MAC table is regenerated)."""
    get_default_context().clear_mac_cache()


random_pool = _ContextProxy("random_pool")
generator = _ContextProxy("generator")
