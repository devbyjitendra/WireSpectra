import sys
import os
import pytest

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from flow_tracker import FlowTracker

def test_flow_expiry_idle_timeout():
    tracker = FlowTracker()
    
    # Packet 1 at timestamp 1000.0
    tracker.process_packet("10.0.0.1", 1234, "10.0.0.2", 80, 6, 100, 1000.0)
    
    # Run cleanup at 1010.0 (idle 10s -> not expired since default is 30s)
    tracker.cleanup_expired_flows(1010.0)
    assert len(tracker.flows) == 1
    assert len(tracker.expired_flows) == 0
    
    # Run cleanup at 1035.0 (idle 35s -> expired)
    tracker.cleanup_expired_flows(1035.0)
    assert len(tracker.flows) == 0
    assert len(tracker.expired_flows) == 1

def test_flow_expiry_closed_timeout():
    tracker = FlowTracker()
    
    # Packet 1 (SYN) at 1000.0
    tracker.process_packet("10.0.0.1", 1234, "10.0.0.2", 80, 6, 100, 1000.0)
    
    # Packet 2 (RST) at 1001.0 (terminates flow immediately)
    tracker.process_packet("10.0.0.2", 80, "10.0.0.1", 1234, 6, 100, 1001.0, rst=True)
    
    flow_key = list(tracker.flows.keys())[0]
    assert tracker.flows[flow_key].state == "CLOSED"
    
    # Run cleanup at 1003.0 (closed for 2s -> not expired since closed timeout is 5s)
    tracker.cleanup_expired_flows(1003.0)
    assert len(tracker.flows) == 1
    
    # Run cleanup at 1007.0 (closed for 6s -> expired)
    tracker.cleanup_expired_flows(1007.0)
    assert len(tracker.flows) == 0
    assert len(tracker.expired_flows) == 1
