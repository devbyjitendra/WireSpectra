import sys
import os
import pytest

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from flow_tracker import FlowTracker

def test_flow_tracker_canonicalization():
    tracker = FlowTracker()
    
    # Packet from A -> B (direction: a_to_b)
    tracker.process_packet(
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol=6, # TCP
        length=100,
        timestamp=1000.0
    )
    
    # Packet from B -> A (direction: b_to_a)
    tracker.process_packet(
        src_ip="10.0.0.2",
        src_port=80,
        dst_ip="10.0.0.1",
        dst_port=1234,
        protocol=6, # TCP
        length=150,
        timestamp=1002.5
    )
    
    # Since it is bidirectional, both packets should merge into 1 flow
    assert len(tracker.flows) == 1
    
    flow_key = list(tracker.flows.keys())[0]
    # Check that endpoints are sorted lexicographically: 10.0.0.1 < 10.0.0.2
    assert flow_key == ("10.0.0.1", 1234, "10.0.0.2", 80, 6)
    
    flow = tracker.flows[flow_key]
    assert flow.packet_count == 2
    assert flow.byte_count == 250
    assert flow.duration == 2.5
    
    # Directional metrics check
    assert flow.packets_a_to_b == 1
    assert flow.packets_b_to_a == 1
    assert flow.bytes_a_to_b == 100
    assert flow.bytes_b_to_a == 150
