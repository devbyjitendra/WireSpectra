import pytest
from src.l7_decoders import L7Decoders
from src.flow_tracker import FlowTracker

def test_ssh_detection():
    # Valid SSH headers
    assert L7Decoders.detect_ssh(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n") is True
    assert L7Decoders.detect_ssh(b"SSH-1.99-OpenSSH_3.9p1\n") is True
    
    # Invalid
    assert L7Decoders.detect_ssh(b"GET /index.html HTTP/1.1") is False
    assert L7Decoders.detect_ssh(b"SSH") is False

def test_dns_detection():
    # Valid DNS query header: ID=1234, Flags=\x01\x00 (standard query, recursion desired), Questions=1, others=0
    dns_query = b"\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x06google\x03com\x00\x00\x01\x00\x01"
    assert L7Decoders.detect_dns(dns_query) is True
    
    # Valid DNS response header: ID=1234, Flags=\x81\x80 (standard response, no error), Questions=1, Answers=1, others=0
    dns_response = b"\x04\xd2\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    assert L7Decoders.detect_dns(dns_response) is True
    
    # Invalid (too short)
    assert L7Decoders.detect_dns(b"\x00\x01\x02") is False
    # Invalid (too many questions)
    bad_dns = b"\x04\xd2\x01\x00\x00\x50\x00\x00\x00\x00\x00\x00"
    assert L7Decoders.detect_dns(bad_dns) is False

def test_ftp_detection():
    # Client command
    assert L7Decoders.detect_ftp(b"USER anonymous\r\n") is True
    assert L7Decoders.detect_ftp(b"PASS guest\r\n") is True
    
    # Server greeting
    assert L7Decoders.detect_ftp(b"220 FTP server ready.\r\n") is True
    assert L7Decoders.detect_ftp(b"220-Welcome to FTP\r\n220 Ready.") is True
    
    # Invalid
    assert L7Decoders.detect_ftp(b"USER") is False
    assert L7Decoders.detect_ftp(b"hello world") is False

def test_flow_tracker_l7_classification():
    tracker = FlowTracker()
    
    # Test SSH flow classification on non-standard port 8022
    flow = tracker.process_packet(
        src_ip="192.168.1.10", src_port=54321,
        dst_ip="10.0.0.5", dst_port=8022,
        protocol=6, length=100, timestamp=100.0,
        payload=b"SSH-2.0-OpenSSH_8.2p1"
    )
    
    assert flow.app_name == "SSH"
    
    # Test DNS flow classification on non-standard port 5353
    dns_payload = b"\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    flow2 = tracker.process_packet(
        src_ip="192.168.1.10", src_port=54322,
        dst_ip="8.8.8.8", dst_port=5353,
        protocol=17, length=50, timestamp=101.0,
        payload=dns_payload
    )
    
    assert flow2.app_name == "DNS"
