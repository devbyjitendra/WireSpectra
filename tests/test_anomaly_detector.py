import sys
import os
import pytest

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from anomaly_detector import AnomalyDetector

def test_port_scan_detection():
    detector = AnomalyDetector(port_threshold=10)
    
    # Query 10 unique ports - no alert yet (should return None)
    for port in range(1, 11):
        alert = detector.process_packet(
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            dst_port=port,
            protocol=6,  # TCP
            tcp_flags=["SYN"]
        )
        assert alert is None
        
    assert len(detector.all_alerts) == 0

    # Query 11th unique port - triggers alert
    alert = detector.process_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        dst_port=11,
        protocol=6,
        tcp_flags=["SYN"]
    )
    assert alert is not None
    assert alert["type"] == "PORT_SCAN"
    assert alert["target"] == "192.168.1.50"
    assert "11 unique ports" in alert["details"]
    assert len(detector.all_alerts) == 1

    # Further scans from the same source IP should not trigger duplicate alerts
    alert = detector.process_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        dst_port=12,
        protocol=6,
        tcp_flags=["SYN"]
    )
    assert alert is None
    assert len(detector.all_alerts) == 1


def test_syn_flood_detection():
    detector = AnomalyDetector(syn_threshold=50)
    
    # Send 50 TCP SYN packets (no ACKs)
    for _ in range(50):
        alert = detector.process_packet(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            dst_port=80,
            protocol=6,
            tcp_flags=["SYN"]
        )
        assert alert is None
        
    assert len(detector.all_alerts) == 0

    # Send 51st SYN - triggers alert
    alert = detector.process_packet(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        dst_port=80,
        protocol=6,
        tcp_flags=["SYN"]
    )
    assert alert is not None
    assert alert["type"] == "SYN_FLOOD"
    assert alert["target"] == "10.0.0.5"
    assert "51 SYNs" in alert["details"]
    assert len(detector.all_alerts) == 1

    # Extra SYNs do not trigger duplicate alerts
    alert = detector.process_packet(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.5",
        dst_port=80,
        protocol=6,
        tcp_flags=["SYN"]
    )
    assert alert is None
    assert len(detector.all_alerts) == 1


def test_syn_flood_normal_ratio():
    detector = AnomalyDetector(syn_threshold=50)
    
    # Send 60 SYN packets but also send 60 ACK packets
    # (ratio is 1.0, which should NOT trigger SYN flood alert)
    for _ in range(60):
        # SYN
        detector.process_packet(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            dst_port=80,
            protocol=6,
            tcp_flags=["SYN"]
        )
        # ACK
        detector.process_packet(
            src_ip="10.0.0.5",
            dst_ip="192.168.1.100",
            dst_port=80,
            protocol=6,
            tcp_flags=["ACK"]
        )
        
    assert len(detector.all_alerts) == 0


def test_custom_thresholds():
    detector = AnomalyDetector(port_threshold=2, syn_threshold=5)
    
    # Port scan custom threshold (triggers on 3rd port)
    for port in [80, 443]:
        assert detector.process_packet("1.1.1.1", "2.2.2.2", port, 6, ["SYN"]) is None
    alert = detector.process_packet("1.1.1.1", "2.2.2.2", 22, 6, ["SYN"])
    assert alert is not None
    assert alert["type"] == "PORT_SCAN"
    
    # SYN flood custom threshold (triggers on 6th SYN)
    for _ in range(5):
        assert detector.process_packet("1.1.1.1", "2.2.2.2", 80, 6, ["SYN"]) is None
    alert = detector.process_packet("1.1.1.1", "2.2.2.2", 80, 6, ["SYN"])
    assert alert is not None
    assert alert["type"] == "SYN_FLOOD"
