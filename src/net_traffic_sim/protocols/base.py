"""Base utilities for protocol generators."""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet

    from ..serializer import FastPacketSerializer

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..state import generator, get_mac_fast, random_pool
from ..tcp import create_tcp_ack, create_tcp_psh_ack, tcp_fin_handshake, tcp_handshake


def _emit_packet(
    serializer: FastPacketSerializer | None,
    packets: list[Packet],
    pkt: Packet,
    timestamp: float,
) -> None:
    """Emit a packet either to the serializer or to a packets list."""
    if serializer is not None:
        serializer.add_packet(pkt, timestamp)
    else:
        packets.append(pkt)


def _udp_packet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
    timestamp: float,
    dst_mac: str | None = None,
) -> Packet:
    """Create a UDP/IPv4 packet."""
    if dst_mac is None:
        dst_mac = get_mac_fast(dst_ip)
    pkt = Ether(src=get_mac_fast(src_ip), dst=dst_mac)
    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id(src_ip, dst_ip))
    pkt /= UDP(sport=sport, dport=dport)
    if payload:
        pkt /= Raw(load=payload)
    pkt.time = timestamp
    return pkt


def _udp6_packet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
    timestamp: float,
    dst_mac: str | None = None,
) -> Packet:
    """Create a UDP/IPv6 packet."""
    if dst_mac is None:
        dst_mac = "33:33:00:00:00:01"
    pkt = Ether(src=get_mac_fast(src_ip), dst=dst_mac)
    pkt /= IPv6(src=src_ip, dst=dst_ip)
    pkt /= UDP(sport=sport, dport=dport)
    if payload:
        pkt /= Raw(load=payload)
    pkt.time = timestamp
    return pkt


def _simple_tcp_exchange(
    src_ip: str,
    dst_ip: str,
    dport: int,
    start_time: float,
    payload: bytes | str,
    response_payload: bytes | str | None = None,
) -> list[Packet]:
    """Create a simple TCP exchange with handshake, data, and optional response.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        dport: Destination port
        start_time: Timestamp for handshake start
        payload: Request payload (required, cannot be empty)
        response_payload: Optional response payload

    Raises:
        ValueError: If payload is None or empty
    """
    # Validate payload is not empty
    if not payload:
        raise ValueError("payload cannot be None or empty")

    packets = []
    sport = random_pool.port()
    handshake = tcp_handshake(src_ip, dst_ip, sport, dport, start_time)
    packets.extend(handshake)

    syn = handshake[0]
    syn_ack = handshake[1]
    conn_client = generator.get_connection(src_ip, dst_ip, sport, dport)
    conn_server = generator.get_connection(dst_ip, src_ip, dport, sport)
    conn_server.seq = syn_ack[TCP].seq + 1
    conn_server.ack = syn[TCP].seq + 1
    conn_server.established = True

    current_time = handshake[-1].time + random_pool.delay_small()
    if payload:
        if isinstance(payload, str):
            payload = payload.encode("ascii", "ignore")
        pkt = create_tcp_psh_ack(
            src_ip,
            dst_ip,
            sport,
            dport,
            conn_client.seq,
            conn_client.ack,
            65535,
            payload,
            current_time,
        )
        packets.append(pkt)
        conn_client.seq += len(payload)
        current_time += random_pool.delay_small()
        ack = create_tcp_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn_client.seq, 65535, current_time)
        packets.append(ack)

    if response_payload:
        current_time += random_pool.delay_small()
        if isinstance(response_payload, str):
            response_payload = response_payload.encode("ascii", "ignore")
        resp = create_tcp_psh_ack(
            dst_ip,
            src_ip,
            dport,
            sport,
            conn_server.seq,
            conn_client.seq,
            65535,
            response_payload,
            current_time,
        )
        packets.append(resp)
        conn_server.seq += len(response_payload)
        current_time += random_pool.delay_small()
        ack2 = create_tcp_ack(src_ip, dst_ip, sport, dport, conn_client.seq, conn_server.seq, 65535, current_time)
        packets.append(ack2)

    return packets


def add_tcp_keepalive(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    timestamp: float,
) -> Packet:
    """Generate TCP Keep-Alive packet (1 byte before current seq)."""
    pkt = Ether(
        src=generator.mac_table.get(src_ip, "00:00:00:00:00:01"),
        dst=generator.mac_table.get(dst_ip, "00:00:00:00:00:02"),
    )
    pkt /= IP(src=src_ip, dst=dst_ip, id=random_pool.ip_id())
    pkt /= TCP(sport=sport, dport=dport, flags="A", seq=seq - 1, ack=ack, window=random.randint(1021, 65535))
    pkt /= Raw(b"\x00")  # 1-byte keepalive payload
    pkt.time = timestamp + random.uniform(0.0, 0.00005)
    return pkt


# =============================================================================
# BaseProtocol Abstract Class
# =============================================================================


class BaseProtocol(ABC):
    """Abstract base class for protocol simulators.

    Provides common helper methods for:
    - Host validation and selection
    - TCP connection helpers (handshake, teardown, data exchange)
    - Payload generation
    - Ephemeral port selection

    Subclasses must implement the `generate()` method.
    """

    def __init__(self, hosts: list[dict[str, str]]):
        """Initialize the protocol simulator with a list of hosts.

        Args:
            hosts: List of host dictionaries with keys 'ip', optionally 'role', 'mac'
        """
        self._validate_hosts(hosts)
        self.hosts = hosts

    def _validate_hosts(self, hosts: list[dict[str, str]]) -> None:
        """Validate that we have at least 2 hosts.

        Args:
            hosts: List of host dictionaries

        Raises:
            ValueError: If less than 2 hosts provided
        """
        if len(hosts) < 2:
            raise ValueError(f"Protocol requires at least 2 hosts, got {len(hosts)}")

    def _get_random_host_pair(self) -> tuple[dict[str, str], dict[str, str]]:
        """Select two random hosts for communication.

        Returns:
            Tuple of (source_host, destination_host) dictionaries
        """
        return random.sample(self.hosts, 2)

    def _get_host_by_role(self, role: str) -> dict[str, str] | None:
        """Find a host with a specific role.

        Args:
            role: Role to search for (e.g., 'server', 'client', 'dc', 'workstation')

        Returns:
            Host dictionary if found, None otherwise
        """
        for host in self.hosts:
            if host.get("role") == role:
                return host
        return None

    def _get_server_client_pair(self, server_role: str) -> tuple[dict[str, str], dict[str, str]]:
        """Get a server-client pair where server has a specific role.

        Args:
            server_role: Role of the server (e.g., 'dc', 'sql_server', 'file_server')

        Returns:
            Tuple of (client_host, server_host) dictionaries

        Raises:
            ValueError: If no host with the specified role exists
        """
        server = self._get_host_by_role(server_role)
        if not server:
            raise ValueError(f"No host with role '{server_role}' found")

        # Pick a random client that's not the server
        clients = [h for h in self.hosts if h.get("ip") != server.get("ip")]
        if not clients:
            raise ValueError(f"No client hosts available (only have server with role '{server_role}')")

        client = random.choice(clients)
        return client, server

    def _generate_random_payload(self, min_size: int, max_size: int) -> bytes:
        """Generate random payload bytes.

        Args:
            min_size: Minimum payload size in bytes
            max_size: Maximum payload size in bytes

        Returns:
            Random bytes of length between min_size and max_size
        """
        size = random.randint(min_size, max_size)
        return bytes(random.getrandbits(8) for _ in range(size))

    def _get_ephemeral_port(self) -> int:
        """Get a random ephemeral port number.

        Returns:
            Port number in the ephemeral range (49152-65535)
        """
        return random.randint(49152, 65535)

    def _generate_tcp_handshake(
        self,
        client: dict[str, str],
        server: dict[str, str],
        client_port: int,
        server_port: int,
        start_time: float,
    ) -> list:
        """Generate a complete TCP 3-way handshake.

        Args:
            client: Client host dictionary with 'ip' key
            server: Server host dictionary with 'ip' key
            client_port: Client source port
            server_port: Server destination port
            start_time: Timestamp for the first SYN packet

        Returns:
            List of 3 packets: [SYN, SYN-ACK, ACK]
        """
        return tcp_handshake(
            client.get("ip"),
            server.get("ip"),
            client_port,
            server_port,
            start_time,
        )

    def _generate_tcp_teardown(
        self,
        client: dict[str, str],
        server: dict[str, str],
        client_port: int,
        server_port: int,
        start_time: float,
    ) -> list:
        """Generate a TCP connection teardown (FIN handshake).

        Args:
            client: Client host dictionary with 'ip' key
            server: Server host dictionary with 'ip' key
            client_port: Client source port
            server_port: Server destination port
            start_time: Timestamp for the first FIN packet

        Returns:
            List of packets for FIN handshake
        """
        return tcp_fin_handshake(
            client.get("ip"),
            server.get("ip"),
            client_port,
            server_port,
            start_time,
        )

    def _generate_tcp_data_exchange(
        self,
        client: dict[str, str],
        server: dict[str, str],
        client_port: int,
        server_port: int,
        request_payload: bytes,
        response_payload: bytes | None,
        start_time: float,
    ) -> list:
        """Generate TCP data exchange with request and optional response.

        Args:
            client: Client host dictionary with 'ip' key
            server: Server host dictionary with 'ip' key
            client_port: Client source port
            server_port: Server destination port
            request_payload: Request data to send from client
            response_payload: Optional response data from server
            start_time: Timestamp for the request packet

        Returns:
            List of packets for data exchange (PSH-ACK, ACK, optional response PSH-ACK, ACK)

        Raises:
            ValueError: If request_payload is empty
        """
        if not request_payload:
            raise ValueError("request_payload cannot be empty")

        packets = []
        client_ip = client.get("ip")
        server_ip = server.get("ip")

        # Get connection state
        conn_client = generator.get_connection(client_ip, server_ip, client_port, server_port)
        conn_server = generator.get_connection(server_ip, client_ip, server_port, client_port)

        current_time = start_time

        # Client sends request
        pkt = create_tcp_psh_ack(
            client_ip,
            server_ip,
            client_port,
            server_port,
            conn_client.seq,
            conn_client.ack,
            65535,
            request_payload,
            current_time,
        )
        packets.append(pkt)
        conn_client.seq += len(request_payload)

        # Server ACKs request
        current_time += random_pool.delay_small()
        ack = create_tcp_ack(
            server_ip,
            client_ip,
            server_port,
            client_port,
            conn_server.seq,
            conn_client.seq,
            65535,
            current_time,
        )
        packets.append(ack)

        # Optional response from server
        if response_payload:
            current_time += random_pool.delay_small()
            resp = create_tcp_psh_ack(
                server_ip,
                client_ip,
                server_port,
                client_port,
                conn_server.seq,
                conn_client.seq,
                65535,
                response_payload,
                current_time,
            )
            packets.append(resp)
            conn_server.seq += len(response_payload)

            # Client ACKs response
            current_time += random_pool.delay_small()
            ack2 = create_tcp_ack(
                client_ip,
                server_ip,
                client_port,
                server_port,
                conn_client.seq,
                conn_server.seq,
                65535,
                current_time,
            )
            packets.append(ack2)

        return packets

    @abstractmethod
    def generate(self, start_time: float, duration: int, packet_count: int = 10) -> list:
        """Generate protocol traffic.

        Args:
            start_time: Starting timestamp for packet generation
            duration: Duration in seconds for the traffic generation
            packet_count: Number of protocol interactions to generate

        Returns:
            List of generated packets
        """
        pass
