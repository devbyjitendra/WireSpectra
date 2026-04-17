import sys
import os
import pytest
import struct

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from protocols import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
from pcap_reader import PcapReader

def test_ethernet_frame_parsing():
    # 14 bytes header: Dst MAC (6 bytes), Src MAC (6 bytes), EtherType (2 bytes) + Payload
    dst_mac = b'\x00\x11\x22\x33\x44\x55'
    src_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    ethertype = struct.pack('>H', 0x0800) # IPv4
    payload = b'Hello World'
    raw_data = dst_mac + src_mac + ethertype + payload

    eth = EthernetFrame(raw_data)
    assert eth.dst_mac == "00:11:22:33:44:55"
    assert eth.src_mac == "aa:bb:cc:dd:ee:ff"
    assert eth.ethertype == 0x0800
    assert eth.get_ethertype_name() == "IPv4"
    assert eth.payload == payload

def test_ethernet_frame_short_data():
    with pytest.raises(ValueError, match="Data too short"):
        EthernetFrame(b'\x00' * 13)

def test_ipv4_packet_parsing():
    # 20 bytes min header:
    # Vers/IHL(1B), TOS(1B), TotalLen(2B), ID(2B), Flags/Frag(2B), TTL(1B), Proto(1B), Checksum(2B), SrcIP(4B), DstIP(4B)
    ver_ihl = 0x45 # Version 4, IHL 5 (20 bytes)
    tos = 0x00
    tot_len = struct.pack('>H', 40)
    ident = struct.pack('>H', 12345)
    flags_frag = struct.pack('>H', 0x4000) # Don't Fragment flag
    ttl = 64
    protocol = 6 # TCP
    checksum = struct.pack('>H', 0x0000)
    src_ip = b'\x0a\x00\x00\x01' # 10.0.0.1
    dst_ip = b'\x0a\x00\x00\x02' # 10.0.0.2
    payload = b'TCP Data'
    raw_data = bytes([ver_ihl, tos]) + tot_len + ident + flags_frag + bytes([ttl, protocol]) + checksum + src_ip + dst_ip + payload

    ip = IPv4Packet(raw_data)
    assert ip.version == 4
    assert ip.ihl == 20
    assert ip.src_ip == "10.0.0.1"
    assert ip.dst_ip == "10.0.0.2"
    assert ip.protocol == 6
    assert ip.get_protocol_name() == "TCP"
    assert ip.payload == payload

def test_ipv4_packet_short_data():
    with pytest.raises(ValueError, match="Data too short"):
        IPv4Packet(b'\x45' * 19)

def test_tcp_packet_parsing():
    # 20 bytes min header:
    # SrcPort(2B), DstPort(2B), Seq(4B), Ack(4B), DataOffset/Reserved(2B), Window(2B), Checksum(2B), UrgPtr(2B)
    src_port = struct.pack('>H', 1234)
    dst_port = struct.pack('>H', 80)
    seq = struct.pack('>I', 1000)
    ack = struct.pack('>I', 2000)
    data_offset_flags = struct.pack('>H', 0x5012) # Offset 5 (20 bytes), SYN-ACK flags (0x02 | 0x10)
    window = struct.pack('>H', 65535)
    checksum = struct.pack('>H', 0)
    urg_ptr = struct.pack('>H', 0)
    payload = b'HTTP GET / HTTP/1.1'
    raw_data = src_port + dst_port + seq + ack + data_offset_flags + window + checksum + urg_ptr + payload

    tcp = TCPPacket(raw_data)
    assert tcp.src_port == 1234
    assert tcp.dst_port == 80
    assert tcp.seq_num == 1000
    assert tcp.ack_num == 2000
    assert tcp.syn is True
    assert tcp.ack is True
    assert tcp.fin is False
    assert tcp.get_flags_str() == "ACK, SYN"
    assert tcp.payload == payload

def test_udp_packet_parsing():
    # 8 bytes header: SrcPort(2B), DstPort(2B), Len(2B), Checksum(2B)
    src_port = struct.pack('>H', 1234)
    dst_port = struct.pack('>H', 53)
    length = struct.pack('>H', 17) # 8 bytes header + 9 bytes payload
    checksum = struct.pack('>H', 0)
    payload = b'DNS Query'
    raw_data = src_port + dst_port + length + checksum + payload

    udp = UDPPacket(raw_data)
    assert udp.src_port == 1234
    assert udp.dst_port == 53
    assert udp.length == 17
    assert udp.payload == payload
