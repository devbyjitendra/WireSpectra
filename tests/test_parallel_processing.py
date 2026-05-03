import sys
import os
import pytest
from click.testing import CliRunner

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from main import decode_packet_batch, main

def test_decode_packet_batch():
    # Build a simple mock TCP packet over IPv4 over Ethernet
    # Ethernet header: 14 bytes
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\x66\x77\x88\x99\xaa\xbb"
    ethertype = b"\x08\x00"  # IPv4
    eth_hdr = dst_mac + src_mac + ethertype
    
    # IPv4 header: 20 bytes
    version_ihl = b"\x45"  # Version 4, IHL 5 (20 bytes)
    tos = b"\x00"
    total_len = b"\x00\x28"  # 40 bytes total (20 IP + 20 TCP)
    ident = b"\x12\x34"
    flags_frag = b"\x00\x00"
    ttl = b"\x40"
    protocol = b"\x06"  # TCP
    checksum = b"\x00\x00"
    src_ip = b"\x0a\x00\x00\x01"  # 10.0.0.1
    dst_ip = b"\x0a\x00\x00\x02"  # 10.0.0.2
    ip_hdr = version_ihl + tos + total_len + ident + flags_frag + ttl + protocol + checksum + src_ip + dst_ip
    
    # TCP header: 20 bytes
    src_port = b"\x04\xd2"  # 1234
    dst_port = b"\x00\x50"  # 80
    seq_num = b"\x00\x00\x00\x01"
    ack_num = b"\x00\x00\x00\x00"
    data_offset_reserved = b"\x50"  # Header length 5 (20 bytes)
    flags = b"\x02"  # SYN flag
    window = b"\xfa\xf0"
    tcp_checksum = b"\x00\x00"
    urg_ptr = b"\x00\x00"
    tcp_hdr = src_port + dst_port + seq_num + ack_num + data_offset_reserved + flags + window + tcp_checksum + urg_ptr
    
    raw_packet = eth_hdr + ip_hdr + tcp_hdr
    
    # Mock PCAP header details
    mock_header = {
        "timestamp": 1718000000.0,
        "length": len(raw_packet),
        "orig_length": len(raw_packet)
    }
    
    # We pass a batch of 1 packet
    batch = [(1, mock_header, raw_packet)]
    
    results = decode_packet_batch(batch)
    
    assert len(results) == 1
    res = results[0]
    assert res["success"] is True
    assert res["is_ip"] is True
    assert res["src_str"] == "10.0.0.1:1234"
    assert res["dst_str"] == "10.0.0.2:80"
    assert "TCP [SYN]" in res["proto_str"]
    
    ip_data = res["ip_data"]
    assert ip_data["src_ip"] == "10.0.0.1"
    assert ip_data["dst_ip"] == "10.0.0.2"
    assert ip_data["src_port"] == 1234
    assert ip_data["dst_port"] == 80
    assert ip_data["protocol"] == 6
    assert ip_data["tcp_flags"] == ["SYN"]


def test_cli_parallel_options():
    runner = CliRunner()
    # Invoke with --help to verify registration of --parallel and --workers
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--parallel" in result.output
    assert "--workers" in result.output
