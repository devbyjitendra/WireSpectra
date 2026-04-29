import os
import logging
import pytest
from src.logger import setup_logger, get_logger

def test_logger_setup_and_filtering(tmp_path):
    log_file = os.path.join(tmp_path, "test_run.log")
    
    # 1. Setup logger at INFO level
    setup_logger("INFO", log_filepath=log_file)
    logger = get_logger("TestModule")
    
    logger.debug("this debug message should NOT be logged")
    logger.info("this info message SHOULD be logged")
    logger.warning("this warning message SHOULD be logged")
    
    # Force close the file handlers to flush logs to disk
    for handler in logging.getLogger("WireSpectra").handlers:
        handler.close()
        
    assert os.path.exists(log_file)
    
    with open(log_file, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert "this debug message" not in content
    assert "this info message" in content
    assert "this warning message" in content
    assert "[INFO] WireSpectra.TestModule:" in content
    assert "[WARNING] WireSpectra.TestModule:" in content

def test_logger_setup_warning_level(tmp_path):
    log_file = os.path.join(tmp_path, "test_run_warning.log")
    
    # 2. Setup logger at WARNING level
    setup_logger("WARNING", log_filepath=log_file)
    logger = get_logger("AnotherModule")
    
    logger.info("this info message should NOT be logged")
    logger.warning("this warning message SHOULD be logged")
    logger.error("this error message SHOULD be logged")
    
    for handler in logging.getLogger("WireSpectra").handlers:
        handler.close()
        
    assert os.path.exists(log_file)
    
    with open(log_file, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert "this info message" not in content
    assert "this warning message" in content
    assert "this error message" in content
    assert "[WARNING] WireSpectra.AnotherModule:" in content
    assert "[ERROR] WireSpectra.AnotherModule:" in content
