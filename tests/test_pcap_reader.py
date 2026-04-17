import sys
import os
import pytest

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from pcap_reader import PcapReader

def test_pcap_reader_file_not_found():
    reader = PcapReader()
    with pytest.raises(FileNotFoundError):
        reader.open("non_existent_file.pcap")

def test_pcap_reader_invalid_header(tmp_path):
    # Create a dummy pcap file with shorter header (10 bytes instead of 24)
    bad_pcap = tmp_path / "bad.pcap"
    bad_pcap.write_bytes(b"\x00" * 10)
    
    reader = PcapReader()
    with pytest.raises(ValueError, match="Invalid PCAP file: Global header too short"):
        reader.open(str(bad_pcap))
