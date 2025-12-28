"""SQL Server (TDS) protocol traffic generators."""

from __future__ import annotations

import random
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    SHAREPOINT_SERVER_IP,
    SQL_SERVER_IP,
    TCP_WINDOW_SQL_CLIENT,
    TCP_WINDOW_SQL_SERVER,
    TDS_BATCH_SIZES,
    TDS_RESPONSE_SIZES,
    TDS_RPC_SIZES,
    Config,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import (
    apply_retransmissions_smart,
    create_tcp_ack,
    create_tcp_fin_ack,
    create_tcp_psh_ack,
    exponential_delay,
    fragment_large_payload,
    get_time_of_day_multiplier,
    inject_duplicate_acks,
    inject_out_of_order_packets,
    should_generate_packet,
    tcp_handshake,
)

logger = get_logger(__name__)


def generate_tds_rpc_payload(size):
    """Generate realistic TDS Remote Procedure Call payload"""
    # TDS header: Type=0x03 (RPC), Status=0x01, Length, SPID, PacketID, Window
    header = struct.pack(">BBHHBB", 0x03, 0x01, size, random.randint(1, 1000), 0, 0)

    # Simulate RPC call data (sp_executesql, stored procedure names, parameters)
    rpc_names = [
        b"sp_executesql",
        b"sp_GetUserPermissions",
        b"sp_MSget_repl_commands",
        b"proc_GetSiteCollections",
        b"proc_GetDocuments",
        b"proc_InsertAuditLog",
    ]
    proc_name = random.choice(rpc_names)

    # Add procedure name and padding
    payload = header + proc_name + b"\x00" * (size - len(header) - len(proc_name))
    return payload[:size]


def generate_tds_batch_payload(size):
    """Generate realistic TDS SQL Batch payload"""
    # TDS header: Type=0x01 (SQL Batch)
    header = struct.pack(">BBHHBB", 0x01, 0x01, size, random.randint(1, 1000), 0, 0)

    # SQL query examples
    queries = [
        b"SELECT TOP 100 * FROM Documents WHERE SiteID = @P1 ORDER BY Modified DESC",
        b"SELECT * FROM UserInfo WHERE UserID = @P1 AND Deleted = 0",
        b"INSERT INTO AuditLog (EventType, UserID, Timestamp) VALUES (@P1, @P2, @P3)",
        b"UPDATE Lists SET ItemCount = ItemCount + 1 WHERE ListID = @P1",
        b"SELECT COUNT(*) FROM Webs WHERE SiteCollectionID = @P1",
        b"SELECT @@VERSION",
    ]
    query = random.choice(queries)

    payload = header + query + b"\x00" * (size - len(header) - len(query))
    return payload[:size]


def generate_tds_response_payload(size):
    """Generate realistic TDS Response payload"""
    # TDS header: Type=0x04 (Response/TabularResult)
    header = struct.pack(">BBHHBB", 0x04, 0x01, size, random.randint(1, 1000), 0, 0)

    # Response tokens: COLMETADATA, ROW, DONE
    # Simplified simulation
    response_data = b"\x81" + b"\x00" * (size - len(header) - 1)  # 0x81 = COLMETADATA token

    payload = header + response_data
    return payload[:size]


def generate_sql_connection_traffic(
    src_ip,
    dst_ip,
    sport,
    start_time,
    duration,
    connection_id,
    sql_queries_per_sec,
):
    """Generate traffic for a single SQL connection over its lifetime with 24-hour awareness"""
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 1433, current_time))
    current_time += random_pool.delay_handshake()

    # Get connection state
    conn = generator.get_connection(src_ip, dst_ip, sport, 1433)
    conn_server = generator.get_connection(dst_ip, src_ip, 1433, sport)

    # TDS Login (simplified - just show handshake)
    login_time = current_time
    login_payload = b"\x12\x01\x00\x00" + b"login_data" + b"\x00" * 200  # Simplified TDS login
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 1433, conn.seq, conn.ack, random.choice(TCP_WINDOW_SQL_CLIENT), login_payload, login_time)
    packets.append(pkt)
    conn.seq += len(login_payload)
    current_time += random_pool.delay_small()

    # Server login response
    login_resp_payload = b"\x04\x01\x00\x00" + b"login_response" + b"\x00" * 150
    pkt = create_tcp_psh_ack(dst_ip, src_ip, 1433, sport, conn_server.seq, conn.seq, random.choice(TCP_WINDOW_SQL_SERVER), login_resp_payload, current_time)
    packets.append(pkt)
    conn_server.seq += len(login_resp_payload)
    conn.ack = conn_server.seq
    current_time += random_pool.delay_tiny()

    # ACK from client
    pkt = create_tcp_ack(src_ip, dst_ip, sport, 1433, conn.seq, conn.ack, random.choice(TCP_WINDOW_SQL_CLIENT), current_time)
    packets.append(pkt)
    current_time += random.uniform(0.005, 0.020)

    # REALISTIC CONNECTION PROFILES: Different connections have different query loads
    connection_profiles = {
        1: {"rate_multiplier": 1.5, "burst_frequency": 0.08},  # High activity (user queries)
        2: {"rate_multiplier": 1.2, "burst_frequency": 0.05},  # Medium-high
        3: {"rate_multiplier": 1.0, "burst_frequency": 0.05},  # Average
        4: {"rate_multiplier": 0.8, "burst_frequency": 0.03},  # Medium-low
        5: {"rate_multiplier": 0.6, "burst_frequency": 0.02},  # Low (batch operations)
        6: {"rate_multiplier": 0.4, "burst_frequency": 0.01},  # Very low (background tasks)
        7: {"rate_multiplier": 0.5, "burst_frequency": 0.02},  # Extra connection if needed
        8: {"rate_multiplier": 0.7, "burst_frequency": 0.03},  # Extra connection if needed
    }

    profile = connection_profiles.get(connection_id, {"rate_multiplier": 1.0, "burst_frequency": 0.05})

    # Calculate queries for THIS connection (not uniform!)
    base_queries = int((duration * sql_queries_per_sec) / 8)  # Base rate divided by avg connections
    max_queries = int(base_queries * profile["rate_multiplier"])

    # Add randomness (+/-10%) to avoid exact multiples
    max_queries = int(max_queries * random.uniform(0.9, 1.1))

    # Query loop - generate queries throughout connection lifetime with time-awareness
    query_count = 0

    while current_time < start_time + duration and query_count < max_queries:
        # TIME-AWARE: Skip queries during off-hours based on probability
        time_multiplier = get_time_of_day_multiplier(current_time)

        # During off-hours, skip most queries
        if time_multiplier < 0.3:  # Off-hours (night/early morning)
            if not should_generate_packet(current_time):
                current_time += random.uniform(5, 30)  # Wait much longer during off-hours
                continue

        # Decide query type
        query_type = random.choices(["rpc", "batch", "rpc"], weights=[60, 30, 10])[0]

        if query_type == "rpc":
            query_size = random.choice(TDS_RPC_SIZES)
            query_payload = generate_tds_rpc_payload(query_size)
        else:
            query_size = random.choice(TDS_BATCH_SIZES)
            query_payload = generate_tds_batch_payload(query_size)

        # Client sends query
        pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 1433, conn.seq, conn.ack, random.choice(TCP_WINDOW_SQL_CLIENT), query_payload, current_time)
        packets.append(pkt)
        conn.seq += len(query_payload)
        current_time += exponential_delay(0.0004, 0.011, 200)  # 0.4-11ms

        # Server ACK
        pkt = create_tcp_ack(dst_ip, src_ip, 1433, sport, conn_server.seq, conn.seq, random.choice(TCP_WINDOW_SQL_SERVER), current_time)
        packets.append(pkt)
        current_time += exponential_delay(0.001, 0.005, 300)

        # Server response
        response_size = random.choice(TDS_RESPONSE_SIZES)
        response_payload = generate_tds_response_payload(response_size)
        pkt = create_tcp_psh_ack(dst_ip, src_ip, 1433, sport, conn_server.seq, conn.seq, random.choice(TCP_WINDOW_SQL_SERVER), response_payload, current_time)

        # Fragment large SQL responses (especially 4KB+ result sets)
        if len(response_payload) > 1460:
            frag_packets = fragment_large_payload(pkt, mss=1460)
            packets.extend(frag_packets)
            conn_server.seq += len(response_payload)
            conn.ack = conn_server.seq
            current_time = float(frag_packets[-1].time) + exponential_delay(0.0004, 0.005, 250)
        else:
            packets.append(pkt)
            conn_server.seq += len(response_payload)
            conn.ack = conn_server.seq
            current_time += exponential_delay(0.0004, 0.005, 250)

        # Client ACK
        pkt = create_tcp_ack(src_ip, dst_ip, sport, 1433, conn.seq, conn.ack, random.choice(TCP_WINDOW_SQL_CLIENT), current_time)
        packets.append(pkt)

        # TIME-AWARE: Adjust delay based on time of day
        if time_multiplier < 0.3:  # Off-hours
            current_time += exponential_delay(0.050, 0.500, 10)  # Much longer delays at night
        else:  # Business hours
            current_time += exponential_delay(0.005, 0.050, 20)  # Normal delays

        query_count += 1

        # Occasional burst pattern (simulating page load) - frequency based on profile
        # Only do bursts during business hours
        if time_multiplier >= 0.7 and random.random() < profile["burst_frequency"]:
            burst_queries = random.randint(5, 15)
            for _ in range(burst_queries):
                if current_time >= start_time + duration:
                    break

                # Check if still in active hours
                if get_time_of_day_multiplier(current_time) < 0.3:
                    break  # Don't burst during off-hours

                # Rapid-fire queries
                query_size = random.choice(TDS_RPC_SIZES)
                query_payload = generate_tds_rpc_payload(query_size)

                pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 1433, conn.seq, conn.ack, random.choice(TCP_WINDOW_SQL_CLIENT), query_payload, current_time)
                packets.append(pkt)
                conn.seq += len(query_payload)
                current_time += exponential_delay(0.0004, 0.003, 500)

                response_size = random.choice(TDS_RESPONSE_SIZES)
                response_payload = generate_tds_response_payload(response_size)

                pkt = create_tcp_psh_ack(
                    dst_ip, src_ip, 1433, sport, conn_server.seq, conn.seq, random.choice(TCP_WINDOW_SQL_SERVER), response_payload, current_time
                )
                packets.append(pkt)
                conn_server.seq += len(response_payload)
                conn.ack = conn_server.seq
                current_time += exponential_delay(0.0004, 0.003, 500)

                query_count += 1

            # Pause after burst
            current_time += random.uniform(0.1, 0.5)

    logger.info(f"    Connection {connection_id} (port {sport}): {query_count} queries generated")
    return packets


def generate_sql_traffic(
    start_time,
    duration,
    serializer: FastPacketSerializer | None = None,
    config: Config | None = None,
):
    """Generate SQL Server traffic with multiple simultaneous connections"""
    logger.info("[+] Generating SQL Server (TDS) traffic...")
    config = config or Config.from_defaults()

    # Determine if we're using serializer or old method
    use_serializer = serializer is not None

    # KEY CHANGE: We NEED to collect packets for post-processing
    # (retransmissions, out-of-order, etc require access to all packets)
    # So we collect in memory, apply transforms, THEN write
    all_packets = []

    # SharePoint maintains 6-8 simultaneous connections to SQL Server
    # Scale connections based on duration and load
    if duration < 3600:  # < 1 hour
        num_connections = random.randint(3, 5)
    elif duration < 86400:  # < 24 hours
        num_connections = random.randint(6, 10)
    else:  # Multi-day
        num_connections = random.randint(8, 15)

    # Allocate ports for connections
    connection_ports = [generator.allocate_port(SHAREPOINT_SERVER_IP) for _ in range(num_connections)]

    logger.info(f"    Creating {num_connections} simultaneous SQL connections")
    logger.info(f"    Ports: {connection_ports}")

    # Generate traffic for each connection independently
    for i, sport in enumerate(connection_ports):
        conn_packets = generate_sql_connection_traffic(
            SHAREPOINT_SERVER_IP,
            SQL_SERVER_IP,
            sport,
            start_time + random.uniform(0, 10),  # Stagger connection starts
            duration,
            i + 1,
            config.sql_queries_per_sec,
        )
        all_packets.extend(conn_packets)

    # Generate 5-10% idle "zombie" connections (common in corporate environments)
    num_idle_connections = max(1, int(num_connections * random.uniform(0.05, 0.10)))
    logger.info(f"    Generating {num_idle_connections} idle connections with keepalives...")

    for _i in range(num_idle_connections):
        idle_sport = generator.allocate_port(SHAREPOINT_SERVER_IP)
        idle_start = start_time + random.uniform(0, duration * 0.3)  # Start within first 30% of duration
        idle_duration = random.uniform(duration * 0.4, duration * 0.9)  # Last 40-90% of capture

        idle_packets = generate_idle_connection_with_keepalives(SHAREPOINT_SERVER_IP, SQL_SERVER_IP, idle_sport, 1433, idle_start, idle_duration)
        all_packets.extend(idle_packets)

    # Apply retransmissions with realistic variance based on connection quality
    connection_quality = random.choices(["pristine", "good", "congested", "problematic"], weights=[20, 50, 25, 5], k=1)[0]

    if connection_quality == "pristine":
        retrans_rate = random.uniform(0.001, 0.005)
    elif connection_quality == "good":
        retrans_rate = random.uniform(0.005, 0.015)
    elif connection_quality == "congested":
        retrans_rate = random.uniform(0.02, 0.03)
    else:  # problematic
        retrans_rate = random.uniform(0.04, 0.05)

    logger.info(f"    Applying {retrans_rate * 100:.1f}% retransmissions ({connection_quality} connection)...")
    all_packets = apply_retransmissions_smart(all_packets, retrans_rate)

    # Apply duplicate ACKs
    if connection_quality == "problematic":
        dupack_rate = random.uniform(0.020, 0.030)
    elif connection_quality == "congested":
        dupack_rate = random.uniform(0.015, 0.020)
    else:
        dupack_rate = random.uniform(0.010, 0.015)

    logger.info(f"    Injecting {dupack_rate * 100:.1f}% duplicate ACKs...")
    all_packets = inject_duplicate_acks(all_packets, dupack_rate)

    # Inject out-of-order packet delivery
    ooo_rate = random.uniform(0.010, 0.020)
    logger.info(f"    Injecting {ooo_rate * 100:.1f}% out-of-order packets...")
    all_packets = inject_out_of_order_packets(all_packets, ooo_rate)

    logger.info(f"    SQL traffic: {len(all_packets)} packets generated")

    #  If serializer provided, write all packets now
    if use_serializer:
        logger.info(f"    Writing {len(all_packets)} SQL packets to PCAP...")
        for pkt in all_packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty list (already written)
    else:
        return all_packets  # Return for backward compatibility


def generate_idle_connection_with_keepalives(src_ip, dst_ip, sport, dport, start_time, duration):
    """
    Generate an idle TCP connection that stays open but sends no data.
    Only sends TCP keepalive probes every 30-120 seconds.
    These "zombie" connections are common in corporate environments.
    """
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, dport, current_time))
    current_time += random_pool.delay_handshake()

    conn = generator.get_connection(src_ip, dst_ip, sport, dport)
    conn_server = generator.get_connection(dst_ip, src_ip, dport, sport)

    # Connection is now established but idle
    # Send keepalive probes periodically
    keepalive_interval = random.uniform(30, 120)  # 30-120 seconds between keepalives
    last_keepalive = current_time

    while current_time < start_time + duration:
        # Wait for keepalive interval
        current_time = last_keepalive + keepalive_interval

        if current_time >= start_time + duration:
            break

        # TCP Keepalive probe (zero-length packet with seq-1)
        # This is how real TCP keepalives work
        keepalive_seq = conn.seq - 1  # One byte BEFORE current sequence
        pkt = create_tcp_ack(src_ip, dst_ip, sport, dport, keepalive_seq, conn.ack, random.choice([8192, 32768, 65535]), current_time)
        packets.append(pkt)

        # Server responds with ACK (keepalive response)
        response_time = current_time + random.uniform(0.001, 0.010)
        pkt = create_tcp_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn.seq, random.choice([8192, 32768, 65535]), response_time)
        packets.append(pkt)

        last_keepalive = current_time
        # Vary the next keepalive interval slightly
        keepalive_interval = random.uniform(30, 120)

    # Connection teardown at the end
    current_time = start_time + duration

    # Client sends FIN
    pkt = create_tcp_fin_ack(src_ip, dst_ip, sport, dport, conn.seq, conn.ack, random.choice([8192, 32768, 65535]), current_time)
    packets.append(pkt)
    conn.seq += 1
    current_time += random.uniform(0.001, 0.005)

    # Server ACKs the FIN
    pkt = create_tcp_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn.seq, random.choice([8192, 32768, 65535]), current_time)
    packets.append(pkt)
    current_time += random.uniform(0.001, 0.005)

    # Server sends FIN
    pkt = create_tcp_fin_ack(dst_ip, src_ip, dport, sport, conn_server.seq, conn.ack, random.choice([8192, 32768, 65535]), current_time)
    packets.append(pkt)
    conn_server.seq += 1
    current_time += random.uniform(0.001, 0.005)

    # Client ACKs the FIN
    pkt = create_tcp_ack(src_ip, dst_ip, sport, dport, conn.seq, conn_server.seq, random.choice([8192, 32768, 65535]), current_time)
    packets.append(pkt)

    return packets


__all__ = [
    "generate_tds_rpc_payload",
    "generate_tds_batch_payload",
    "generate_tds_response_payload",
    "generate_sql_connection_traffic",
    "generate_sql_traffic",
    "generate_idle_connection_with_keepalives",
]
