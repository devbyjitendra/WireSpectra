import pytest
from src.rules_engine import Rule, RulesEngine
from src.flow_tracker import Flow

def test_rule_payload_text_signature():
    rule = Rule(rule_id="r_text", action="ALERT", payload_pattern="malware_signature")
    
    assert rule.matches("1.1.1.1", 1234, "2.2.2.2", 80, 6, payload=b"some header malware_signature trailer") is True
    assert rule.matches("1.1.1.1", 1234, "2.2.2.2", 80, 6, payload=b"normal traffic") is False
    assert rule.matches("1.1.1.1", 1234, "2.2.2.2", 80, 6, payload=b"") is False

def test_rule_payload_regex_signature():
    rule = Rule(rule_id="r_regex", action="BLOCK", payload_pattern=r"select.*from.*users")
    
    # Matches case-insensitively due to re.IGNORECASE
    assert rule.matches("1.1.1.1", 1234, "2.2.2.2", 80, 6, payload=b"SELECT id, name FROM users WHERE 1=1") is True
    assert rule.matches("1.1.1.1", 1234, "2.2.2.2", 80, 6, payload=b"select from accounts") is False

def test_rule_payload_binary_signature():
    # Test bytes signature (hex pattern)
    rule = Rule(rule_id="r_bin", action="BLOCK", payload_pattern=b"\x00\xff\x00")
    
    assert rule.matches("1.1.1.1", 1234, "2.2.2.2", 80, 6, payload=b"\xaa\xbb\x00\xff\x00\xcc") is True
    assert rule.matches("1.1.1.1", 1234, "2.2.2.2", 80, 6, payload=b"\xaa\xbb\x00\xee\x00\xcc") is False

def test_rules_engine_payload_evaluation():
    engine = RulesEngine()
    engine.load_rules([
        {"rule_id": "rule_sql", "action": "BLOCK", "payload_pattern": "union select"},
        {"rule_id": "rule_http", "action": "ALERT", "dst_port": 80}
    ])
    
    # Matches SQL pattern
    match1 = engine.evaluate_packet(
        src_ip="192.168.1.5", src_port=1234, dst_ip="10.0.0.1", dst_port=80, protocol=6,
        payload=b"GET /index.php?id=1%20union%20select%201,2,3"
    )
    assert match1 is not None
    assert match1.rule_id == "rule_sql"
    
    # Fallback to port match when SQL pattern is not matched
    match2 = engine.evaluate_packet(
        src_ip="192.168.1.5", src_port=1234, dst_ip="10.0.0.1", dst_port=80, protocol=6,
        payload=b"GET /index.html"
    )
    assert match2 is not None
    assert match2.rule_id == "rule_http"
