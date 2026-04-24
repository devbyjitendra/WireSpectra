import pytest
from src.rules_engine import Rule, RulesEngine
from src.flow_tracker import Flow

def test_rule_matching_ip():
    rule = Rule(rule_id="r1", action="ALERT", src_ip="192.168.1.0/24")
    
    # Matching IP in subnet
    assert rule.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=80, protocol=6) is True
    # Bidirectional matching (dst matches rule.src_ip)
    assert rule.matches(src_ip="10.0.0.1", src_port=80, dst_ip="192.168.1.50", dst_port=1234, protocol=6) is True
    # Non-matching IP
    assert rule.matches(src_ip="192.168.2.50", src_port=1234, dst_ip="10.0.0.1", dst_port=80, protocol=6) is False

def test_rule_matching_ports():
    # Single port
    rule_single = Rule(rule_id="r2", action="BLOCK", dst_port=80)
    assert rule_single.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=80, protocol=6) is True
    assert rule_single.matches(src_ip="192.168.1.50", src_port=80, dst_ip="10.0.0.1", dst_port=1234, protocol=6) is True
    assert rule_single.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443, protocol=6) is False

    # Port range
    rule_range = Rule(rule_id="r3", action="ALERT", dst_port="80-90")
    assert rule_range.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=85, protocol=6) is True
    assert rule_range.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=95, protocol=6) is False

    # Port list
    rule_list = Rule(rule_id="r4", action="ALERT", dst_port="80,443,8080")
    assert rule_list.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443, protocol=6) is True
    assert rule_list.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=8080, protocol=6) is True
    assert rule_list.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=80, protocol=6) is True
    assert rule_list.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=22, protocol=6) is False

def test_rule_matching_domain():
    # Exact domain match
    rule_exact = Rule(rule_id="r5", action="ALERT", domain="google.com")
    assert rule_exact.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443, protocol=6, domain="google.com") is True
    assert rule_exact.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443, protocol=6, domain="sub.google.com") is False

    # Wildcard domain match
    rule_wildcard = Rule(rule_id="r6", action="ALERT", domain="*.google.com")
    assert rule_wildcard.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443, protocol=6, domain="google.com") is True
    assert rule_wildcard.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443, protocol=6, domain="sub.google.com") is True
    assert rule_wildcard.matches(src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443, protocol=6, domain="other.com") is False

def test_rules_engine_eval():
    engine = RulesEngine()
    engine.load_rules([
        {"rule_id": "rule_block_http", "action": "BLOCK", "protocol": "TCP", "dst_port": 80},
        {"rule_id": "rule_alert_dns", "action": "ALERT", "protocol": "UDP", "dst_port": 53},
        {"rule_id": "rule_malicious_subnet", "action": "BLOCK", "src_ip": "198.51.100.0/24"}
    ])

    # Evaluate TCP port 80 packet
    match1 = engine.evaluate_packet(src_ip="192.168.1.50", src_port=1234, dst_ip="1.1.1.1", dst_port=80, protocol=6)
    assert match1 is not None
    assert match1.rule_id == "rule_block_http"
    assert match1.action == "BLOCK"

    # Evaluate UDP port 53 packet
    match2 = engine.evaluate_packet(src_ip="192.168.1.50", src_port=1234, dst_ip="8.8.8.8", dst_port=53, protocol=17)
    assert match2 is not None
    assert match2.rule_id == "rule_alert_dns"
    assert match2.action == "ALERT"

    # Evaluate flow object matching
    flow_key = ("198.51.100.10", 4321, "8.8.8.8", 443, 6)
    flow = Flow(flow_key=flow_key, protocol_name="TCP", start_time=100.0)
    
    match3 = engine.evaluate_flow(flow)
    assert match3 is not None
    assert match3.rule_id == "rule_malicious_subnet"
    assert match3.action == "BLOCK"
