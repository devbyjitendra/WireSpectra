import os
import json
import time
import pytest
from src.rules_engine import RulesEngine

def test_rules_engine_hot_reload(tmp_path):
    rules_file = os.path.join(tmp_path, "rules.json")
    
    initial_rules = [
        {"rule_id": "r1", "action": "BLOCK", "protocol": "TCP", "dst_port": 80}
    ]
    
    with open(rules_file, "w") as f:
        json.dump(initial_rules, f)
        
    engine = RulesEngine()
    engine.load_rules_from_file(rules_file)
    
    assert len(engine.rules) == 1
    assert engine.rules[0].rule_id == "r1"
    
    # 1. Calling check_and_reload when file is not modified should return False
    assert engine.check_and_reload() is False
    assert len(engine.rules) == 1
    
    # 2. Modify rules and update the file's modification time (mtime)
    updated_rules = [
        {"rule_id": "r1", "action": "BLOCK", "protocol": "TCP", "dst_port": 80},
        {"rule_id": "r2", "action": "ALERT", "protocol": "UDP", "dst_port": 53}
    ]
    
    # Set mtime forward by a few seconds to guarantee mtime change is registered
    curr_mtime = os.path.getmtime(rules_file)
    new_mtime = curr_mtime + 5.0
    
    with open(rules_file, "w") as f:
        json.dump(updated_rules, f)
        
    os.utime(rules_file, (new_mtime, new_mtime))
    
    # 3. Check and reload should detect modification, reload rules, and return True
    assert engine.check_and_reload() is True
    assert len(engine.rules) == 2
    assert engine.rules[1].rule_id == "r2"
    
    # 4. Successive check should return False
    assert engine.check_and_reload() is False
