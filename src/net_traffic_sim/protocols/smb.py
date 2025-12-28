"""SMB (Server Message Block) protocol traffic generators."""

from __future__ import annotations

import random
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..serializer import FastPacketSerializer

from ..config import (
    FILE_SHARE_SERVER_IP,
    FILE_TRANSFERS,
    RETRANSMISSION_RATE_OTHER,
    TCP_WINDOW_SMB_CLIENT,
    TCP_WINDOW_SMB_SERVER,
)
from ..logging_setup import get_logger
from ..state import generator, random_pool
from ..tcp import (
    apply_retransmissions_smart,
    create_tcp_ack,
    create_tcp_psh_ack,
    exponential_delay,
    fragment_large_payload,
    safe_packet_size,
    tcp_handshake,
)

logger = get_logger(__name__)


def generate_smb2_negotiate():
    """Generate SMB2 Negotiate Protocol Request"""
    # Simplified SMB2 header
    smb2_header = b"\xfe\x53\x4d\x42"  # SMB2 signature
    smb2_header += b"\x40\x00"  # Header length
    smb2_header += b"\x00\x00"  # Credit charge
    smb2_header += b"\x00\x00"  # Status
    smb2_header += b"\x00\x00"  # Command: Negotiate (0x0000)
    smb2_header += struct.pack("<Q", random.randint(1, 1000))  # Message ID
    smb2_header += b"\x00" * 16  # Reserved, Tree ID, Session ID

    # Negotiate request body
    negotiate = b"\x24\x00"  # Structure size
    negotiate += b"\x05\x00"  # Dialect count
    negotiate += b"\x00\x00"  # Security mode
    negotiate += b"\x00\x00"  # Reserved
    negotiate += b"\x00" * 16  # Client GUID

    # Dialects: SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
    negotiate += b"\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03"

    return smb2_header + negotiate


def generate_smb2_negotiate_response():
    """Generate SMB2 Negotiate Protocol Response"""
    smb2_header = b"\xfe\x53\x4d\x42"
    smb2_header += b"\x40\x00"
    smb2_header += b"\x00\x00"
    smb2_header += b"\x00\x00\x00\x00"  # Status: SUCCESS
    smb2_header += b"\x00\x00"  # Command: Negotiate
    smb2_header += struct.pack("<Q", random.randint(1, 1000))
    smb2_header += b"\x00" * 16

    # Negotiate response body
    response = b"\x41\x00"  # Structure size
    response += b"\x00\x00"  # Security mode
    response += b"\x11\x03"  # Dialect: SMB 3.1.1
    response += b"\x00" * 16  # Server GUID
    response += b"\x00" * 20  # Capabilities, system time, etc.

    return smb2_header + response


def generate_smb2_session_setup():
    """Generate SMB2 Session Setup Request (NTLMSSP_NEGOTIATE)"""
    smb2_header = b"\xfe\x53\x4d\x42"
    smb2_header += b"\x40\x00"
    smb2_header += b"\x00\x00\x00\x00"
    smb2_header += b"\x01\x00"  # Command: Session Setup
    smb2_header += struct.pack("<Q", random.randint(1, 1000))
    smb2_header += b"\x00" * 16

    # Session setup body with NTLMSSP
    setup = b"\x19\x00"  # Structure size
    setup += b"\x00"  # Flags
    setup += b"\x00"  # Security mode
    setup += b"\x00" * 8  # Capabilities, channel, etc.

    # NTLMSSP_NEGOTIATE
    ntlmssp = b"NTLMSSP\x00"
    ntlmssp += b"\x01\x00\x00\x00"  # Message type: NEGOTIATE
    ntlmssp += b"\x00" * 32  # Flags and version info

    setup += struct.pack("<H", len(ntlmssp))
    setup += ntlmssp

    return smb2_header + setup


def generate_smb2_tree_connect(share_name):
    """Generate SMB2 Tree Connect Request"""
    smb2_header = b"\xfe\x53\x4d\x42"
    smb2_header += b"\x40\x00"
    smb2_header += b"\x00\x00\x00\x00"
    smb2_header += b"\x03\x00"  # Command: Tree Connect
    smb2_header += struct.pack("<Q", random.randint(1, 1000))
    smb2_header += b"\x00" * 16

    # Tree connect body
    path = f"\\\\{FILE_SHARE_SERVER_IP}\\{share_name}".encode("utf-16le")
    tree_connect = b"\x09\x00"  # Structure size
    tree_connect += b"\x00\x00"  # Reserved
    tree_connect += struct.pack("<H", len(path))  # Path length
    tree_connect += path

    return smb2_header + tree_connect


def generate_smb2_create_request(filename):
    """Generate SMB2 Create Request (file open)"""
    smb2_header = b"\xfe\x53\x4d\x42"
    smb2_header += b"\x40\x00"
    smb2_header += b"\x00\x00\x00\x00"
    smb2_header += b"\x05\x00"  # Command: Create
    smb2_header += struct.pack("<Q", random.randint(1, 1000))
    smb2_header += b"\x00" * 16

    # Create request body
    create = b"\x39\x00"  # Structure size
    create += b"\x00"  # Security flags
    create += b"\x00"  # Requested oplock level
    create += b"\x00\x00\x00\x00"  # Impersonation level
    create += b"\x00" * 16  # Create flags and reserved
    create += b"\x80\x00\x10\x00"  # Desired access: GENERIC_READ
    create += b"\x00\x00\x00\x00"  # File attributes
    create += b"\x00\x00\x00\x00"  # Share access
    create += b"\x01\x00\x00\x00"  # Create disposition: FILE_OPEN
    create += b"\x00\x00\x00\x00"  # Create options

    # Filename
    filename_bytes = filename.encode("utf-16le")
    create += struct.pack("<H", len(filename_bytes))
    create += filename_bytes

    return smb2_header + create


def generate_smb2_read_request(file_id, offset, length):
    """Generate SMB2 Read Request"""
    smb2_header = b"\xfe\x53\x4d\x42"
    smb2_header += b"\x40\x00"
    smb2_header += b"\x00\x00\x00\x00"
    smb2_header += b"\x08\x00"  # Command: Read
    smb2_header += struct.pack("<Q", random.randint(1, 1000))
    smb2_header += b"\x00" * 16

    # Read request body
    read_req = b"\x31\x00"  # Structure size
    read_req += b"\x00"  # Padding
    read_req += b"\x00"  # Reserved
    read_req += struct.pack("<I", length)  # Length
    read_req += struct.pack("<Q", offset)  # Offset
    read_req += file_id  # File ID (16 bytes)
    read_req += b"\x00\x00\x00\x00"  # Minimum count
    read_req += b"\x00\x00\x00\x00"  # Channel, remaining bytes

    return smb2_header + read_req


def generate_smb2_read_response(data_length):
    """Generate SMB2 Read Response"""
    smb2_header = b"\xfe\x53\x4d\x42"
    smb2_header += b"\x40\x00"
    smb2_header += b"\x00\x00\x00\x00"  # Status: SUCCESS
    smb2_header += b"\x08\x00"  # Command: Read
    smb2_header += struct.pack("<Q", random.randint(1, 1000))
    smb2_header += b"\x00" * 16

    # Read response body
    read_resp = b"\x11\x00"  # Structure size
    read_resp += b"\x00"  # Data offset
    read_resp += b"\x00" * 3  # Reserved
    read_resp += struct.pack("<I", data_length)  # Data length
    read_resp += b"\x00" * 4  # Remaining

    # SAFE SIZE: Cap data to prevent packet size overflow
    safe_data_length = safe_packet_size(data_length, headers_size=len(smb2_header) + len(read_resp))

    # Simulate file data
    read_resp += b"\x00" * safe_data_length

    return smb2_header + read_resp


def generate_smb2_close():
    """Generate SMB2 Close Request"""
    smb2_header = b"\xfe\x53\x4d\x42"
    smb2_header += b"\x40\x00"
    smb2_header += b"\x00\x00\x00\x00"
    smb2_header += b"\x06\x00"  # Command: Close
    smb2_header += struct.pack("<Q", random.randint(1, 1000))
    smb2_header += b"\x00" * 16

    # Close request body
    close = b"\x18\x00"  # Structure size
    close += b"\x00\x00"  # Flags
    close += b"\x00" * 16  # File ID

    return smb2_header + close


def generate_smb_file_transfer(src_ip, dst_ip, sport, filename, filesize, start_time, is_upload=False):
    """Generate complete SMB file transfer session (download or upload)"""
    packets = []
    current_time = start_time

    # TCP handshake
    packets.extend(tcp_handshake(src_ip, dst_ip, sport, 445, current_time))
    current_time += random_pool.delay_handshake()

    conn = generator.get_connection(src_ip, dst_ip, sport, 445)
    conn_server = generator.get_connection(dst_ip, src_ip, 445, sport)

    # SMB2 Negotiate
    negotiate = generate_smb2_negotiate()
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 445, conn.seq, conn.ack, TCP_WINDOW_SMB_CLIENT, negotiate, current_time)
    packets.append(pkt)
    conn.seq += len(negotiate)
    current_time += exponential_delay(0.001, 0.005, 300)

    # Server Negotiate Response
    neg_resp = generate_smb2_negotiate_response()
    pkt = create_tcp_psh_ack(dst_ip, src_ip, 445, sport, conn_server.seq, conn.seq, TCP_WINDOW_SMB_SERVER, neg_resp, current_time)
    packets.append(pkt)
    conn_server.seq += len(neg_resp)
    conn.ack = conn_server.seq
    current_time += exponential_delay(0.001, 0.005, 300)

    # Session Setup (simplified - just one exchange)
    session_setup = generate_smb2_session_setup()
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 445, conn.seq, conn.ack, TCP_WINDOW_SMB_CLIENT, session_setup, current_time)
    packets.append(pkt)
    conn.seq += len(session_setup)
    current_time += exponential_delay(0.001, 0.005, 300)

    # Session Setup Response (STATUS_SUCCESS)
    session_resp = b"\xfe\x53\x4d\x42" + b"\x00" * 60  # Simplified
    pkt = create_tcp_psh_ack(dst_ip, src_ip, 445, sport, conn_server.seq, conn.seq, TCP_WINDOW_SMB_SERVER, session_resp, current_time)
    packets.append(pkt)
    conn_server.seq += len(session_resp)
    conn.ack = conn_server.seq
    current_time += exponential_delay(0.001, 0.005, 300)

    # Tree Connect
    share = "Backups" if is_upload else random.choice(["Software", "ISO", "Updates"])
    tree_conn = generate_smb2_tree_connect(share)
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 445, conn.seq, conn.ack, TCP_WINDOW_SMB_CLIENT, tree_conn, current_time)
    packets.append(pkt)
    conn.seq += len(tree_conn)
    current_time += exponential_delay(0.001, 0.005, 300)

    # Tree Connect Response
    tree_resp = b"\xfe\x53\x4d\x42" + b"\x00" * 50
    pkt = create_tcp_psh_ack(dst_ip, src_ip, 445, sport, conn_server.seq, conn.seq, TCP_WINDOW_SMB_SERVER, tree_resp, current_time)
    packets.append(pkt)
    conn_server.seq += len(tree_resp)
    conn.ack = conn_server.seq
    current_time += exponential_delay(0.001, 0.005, 300)

    # Create (file open)
    create_req = generate_smb2_create_request(filename)
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 445, conn.seq, conn.ack, TCP_WINDOW_SMB_CLIENT, create_req, current_time)
    packets.append(pkt)
    conn.seq += len(create_req)
    current_time += exponential_delay(0.001, 0.005, 300)

    # Create Response (with file handle)
    file_id = struct.pack("<Q", random.randint(1, 100000)) + b"\x00" * 8
    create_resp = b"\xfe\x53\x4d\x42" + b"\x00" * 40 + file_id
    pkt = create_tcp_psh_ack(dst_ip, src_ip, 445, sport, conn_server.seq, conn.seq, TCP_WINDOW_SMB_SERVER, create_resp, current_time)
    packets.append(pkt)
    conn_server.seq += len(create_resp)
    conn.ack = conn_server.seq
    current_time += exponential_delay(0.001, 0.005, 300)

    # Note: Read/Write loop with DYNAMIC chunk size based on file size
    # Modern SMB uses larger chunks for big files, smaller for small files
    if filesize > 500_000_000:  # Large files (>500MB) - ISOs, backups
        chunk_size = random.choice([65536, 131072, 262144, 524288])  # 64KB-512KB
    else:  # Smaller files - Office docs, executables
        chunk_size = random.choice([8192, 16384, 32768, 65536])  # 8KB-64KB

    offset = 0
    bytes_transferred = 0

    while bytes_transferred < filesize:
        # Read request
        read_length = min(chunk_size, filesize - bytes_transferred)
        read_req = generate_smb2_read_request(file_id, offset, read_length)

        pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 445, conn.seq, conn.ack, TCP_WINDOW_SMB_CLIENT, read_req, current_time)
        packets.append(pkt)
        conn.seq += len(read_req)
        current_time += exponential_delay(0.0001, 0.001, 1000)

        # Read response with data
        read_resp = generate_smb2_read_response(read_length)
        pkt = create_tcp_psh_ack(dst_ip, src_ip, 445, sport, conn_server.seq, conn.seq, TCP_WINDOW_SMB_SERVER, read_resp, current_time)

        # Fragment if payload exceeds MSS (1460 bytes)
        # This happens frequently with SMB read responses (64KB-512KB chunks)
        if len(read_resp) > 1460:
            frag_packets = fragment_large_payload(pkt, mss=1460)
            packets.extend(frag_packets)
            # Update sequence number to account for all fragments
            conn_server.seq += len(read_resp)
            conn.ack = conn_server.seq
            # Time already updated by fragment_large_payload
            current_time = float(frag_packets[-1].time) + exponential_delay(0.0001, 0.001, 1000)

        else:
            packets.append(pkt)
            conn_server.seq += len(read_resp)
            conn.ack = conn_server.seq
            current_time += exponential_delay(0.0001, 0.001, 1000)

        # Client ACK
        pkt = create_tcp_ack(src_ip, dst_ip, sport, 445, conn.seq, conn.ack, TCP_WINDOW_SMB_CLIENT, current_time)
        packets.append(pkt)

        offset += read_length
        bytes_transferred += read_length

        # Small delay every 10 chunks
        if (bytes_transferred // chunk_size) % 10 == 0:
            current_time += exponential_delay(0.010, 0.050, 50)
        else:
            current_time += exponential_delay(0.0001, 0.005, 500)

    # Close request
    close_req = generate_smb2_close()
    pkt = create_tcp_psh_ack(src_ip, dst_ip, sport, 445, conn.seq, conn.ack, TCP_WINDOW_SMB_CLIENT, close_req, current_time)
    packets.append(pkt)
    conn.seq += len(close_req)
    current_time += exponential_delay(0.001, 0.005, 300)

    # Close response
    close_resp = b"\xfe\x53\x4d\x42" + b"\x00" * 40
    pkt = create_tcp_psh_ack(dst_ip, src_ip, 445, sport, conn_server.seq, conn.seq, TCP_WINDOW_SMB_SERVER, close_resp, current_time)
    packets.append(pkt)

    return packets


def generate_smb_traffic(
    start_time,
    duration,
    smb_simulated_size=20_000_000,
    max_transfers=None,
    enforce_short_run_caps=True,
    serializer: FastPacketSerializer | None = None,
):
    """Generate SMB file transfer traffic"""
    logger.info("[+] Generating SMB file transfer traffic...")

    use_serializer = serializer is not None
    all_packets = []

    smb_transfers = [ft for ft in FILE_TRANSFERS if ft[2] == "smb"]
    transfer_count = 0
    transfer_limit = len(smb_transfers)
    if enforce_short_run_caps:
        transfer_limit = min(transfer_limit, 15)
    if max_transfers is not None:
        transfer_limit = min(transfer_limit, max_transfers)

    for filename, filesize, _protocol, source, dest_ip in smb_transfers[:transfer_limit]:
        # SCHEDULE BASED ON FILE TYPE:
        if "Backup" in filename or ".bak" in filename:
            # Backups happen at night (10 PM - 4 AM)
            night_start = 22 * 3600  # 10 PM
            night_end = 28 * 3600  # 4 AM next day
            transfer_start = start_time + random.uniform(night_start, night_end)
        elif filesize > 1_000_000_000:  # Large files (ISOs) - late afternoon/evening
            afternoon_start = 15 * 3600  # 3 PM
            afternoon_end = 19 * 3600  # 7 PM
            transfer_start = start_time + random.uniform(afternoon_start, afternoon_end)
        else:  # Regular files - business hours
            business_start = 8 * 3600
            business_end = 17 * 3600
            transfer_start = start_time + random.uniform(business_start, business_end)

        sport = generator.allocate_port(source if source == FILE_SHARE_SERVER_IP else dest_ip)
        is_upload = dest_ip == FILE_SHARE_SERVER_IP

        # Only generate small/medium files completely, simulate large files partially
        if filesize > 100_000_000:  # > 100MB
            simulated_size = min(filesize, smb_simulated_size)
            direction = "upload to" if is_upload else "download from"
            logger.info(
                f"    Transfer: {filename} ({filesize / (1024**3):.2f} GB) {direction} {FILE_SHARE_SERVER_IP} - simulating {simulated_size / (1024**2):.0f}MB"
            )
        else:
            simulated_size = filesize
            direction = "upload to" if is_upload else "download from"
            logger.info(f"    Transfer: {filename} ({filesize / (1024**2):.1f} MB) {direction} {FILE_SHARE_SERVER_IP}")

        if is_upload:
            # Upload: source -> FILE_SHARE_SERVER_IP
            transfer_packets = generate_smb_file_transfer(source, FILE_SHARE_SERVER_IP, sport, filename, int(simulated_size), transfer_start, is_upload=True)
        else:
            # Download: FILE_SHARE_SERVER_IP -> dest_ip
            transfer_packets = generate_smb_file_transfer(dest_ip, FILE_SHARE_SERVER_IP, sport, filename, int(simulated_size), transfer_start, is_upload=False)

        all_packets.extend(transfer_packets)
        transfer_count += 1

    # Apply light retransmissions KEPT
    all_packets = apply_retransmissions_smart(all_packets, RETRANSMISSION_RATE_OTHER)

    logger.info(f"    SMB traffic: {len(all_packets)} packets ({transfer_count} transfers)")

    # Write packets if serializer provided, otherwise return
    if use_serializer:
        logger.info(f"    Writing {len(all_packets)} SMB packets to PCAP...")
        for pkt in all_packets:
            serializer.add_packet(pkt, pkt.time)
        return []  # Return empty (already written)
    else:
        return all_packets  # Return for backward compatibility


__all__ = [
    "generate_smb2_negotiate",
    "generate_smb2_negotiate_response",
    "generate_smb2_session_setup",
    "generate_smb2_tree_connect",
    "generate_smb2_create_request",
    "generate_smb2_read_request",
    "generate_smb2_read_response",
    "generate_smb2_close",
    "generate_smb_file_transfer",
    "generate_smb_traffic",
]
