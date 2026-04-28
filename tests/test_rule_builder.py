import os
import json
import pytest
from src.rule_builder import (
    validate_action,
    validate_protocol,
    validate_ip,
    validate_ports,
    InteractiveRuleBuilder
)

def test_validate_action():
    assert validate_action("alert") == "ALERT"
    assert validate_action("BLOCK") == "BLOCK"
    with pytest.raises(ValueError):
        validate_action("drop")
    with pytest.raises(ValueError):
        validate_action("")

def test_validate_protocol():
    assert validate_protocol("tcp") == "TCP"
    assert validate_protocol("UDP") == "UDP"
    assert validate_protocol("6") == 6
    assert validate_protocol("") is None
    with pytest.raises(ValueError):
        validate_protocol("http")
    with pytest.raises(ValueError):
        validate_protocol("256")

def test_validate_ip():
    assert validate_ip("192.168.1.1") == "192.168.1.1"
    assert validate_ip("10.0.0.0/8") == "10.0.0.0/8"
    assert validate_ip("") is None
    with pytest.raises(ValueError):
        validate_ip("invalid-ip")

def test_validate_ports():
    assert validate_ports("80") == 80
    assert validate_ports(443) == 443
    assert validate_ports("80-90") == "80-90"
    assert validate_ports("80,443,8080") == "80,443,8080"
    assert validate_ports("") is None
    with pytest.raises(ValueError):
        validate_ports("invalid-port")
    with pytest.raises(ValueError):
        validate_ports("80-70")  # start > end
    with pytest.raises(ValueError):
        validate_ports("0")
    with pytest.raises(ValueError):
        validate_ports("65536")

def test_save_rule_to_file(tmp_path):
    rules_file = os.path.join(tmp_path, "rules.json")
    
    rule1 = {"rule_id": "r1", "action": "BLOCK"}
    rule2 = {"rule_id": "r2", "action": "ALERT", "protocol": "TCP", "dst_port": 80}
    
    # Save first rule
    InteractiveRuleBuilder.save_rule_to_file(rule1, rules_file)
    assert os.path.exists(rules_file)
    
    with open(rules_file, "r") as f:
        data = json.load(f)
        assert len(data) == 1
        assert data[0]["rule_id"] == "r1"
        
    # Append second rule
    InteractiveRuleBuilder.save_rule_to_file(rule2, rules_file)
    
    with open(rules_file, "r") as f:
        data = json.load(f)
        assert len(data) == 2
        assert data[1]["rule_id"] == "r2"
        assert data[1]["dst_port"] == 80
