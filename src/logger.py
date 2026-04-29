import logging
import os
import sys

def setup_logger(level_name: str, log_filepath: str = None):
    """
    Configures the root logger for WireSpectra.
    """
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    level = level_map.get(level_name.upper(), logging.INFO)
    
    # Formatter layout
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    root_logger = logging.getLogger("WireSpectra")
    root_logger.setLevel(level)
    
    # Clear any previous handlers
    root_logger.handlers = []
    
    # Console Handler (writes to stderr so click stdout pipelines are not polluted)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # File Handler
    if log_filepath:
        log_dir = os.path.dirname(log_filepath)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        file_handler = logging.FileHandler(log_filepath, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        root_logger.addHandler(file_handler)
        
    return root_logger

def get_logger(module_name: str):
    """
    Gets a child logger for a specific module.
    """
    return logging.getLogger(f"WireSpectra.{module_name}")
