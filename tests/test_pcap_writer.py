import os
import pytest
from src.pcap_writer import PcapWriter
from src.pcap_reader import PcapReader

def test_pcap_write_and_read(tmp_path):
    pcap_path = os.path.join(tmp_path, "test.pcap")
    
    writer = PcapWriter()
    writer.open(pcap_path, network=1, snaplen=65535)
    
    packet_1_data = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    packet_2_data = b"\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
    
    timestamp_1 = 1718000000.123456
    timestamp_2 = 1718000001.654321
    
    writer.write_packet(timestamp_1, packet_1_data)
    writer.write_packet(timestamp_2, packet_2_data)
    writer.close()
    
    # Read them back using PcapReader
    reader = PcapReader()
    reader.open(pcap_path)
    
    assert reader.magic_number == 0xa1b2c3d4
    assert reader.version_major == 2
    assert reader.version_minor == 4
    assert reader.network == 1
    assert reader.snaplen == 65535
    
    packets = list(reader)
    reader.close()
    
    assert len(packets) == 2
    
    # Verify Packet 1
    hdr_1, data_1 = packets[0]
    assert pytest.approx(hdr_1["timestamp"], abs=1e-6) == timestamp_1
    assert hdr_1["length"] == len(packet_1_data)
    assert data_1 == packet_1_data
    
    # Verify Packet 2
    hdr_2, data_2 = packets[1]
    assert pytest.approx(hdr_2["timestamp"], abs=1e-6) == timestamp_2
    assert hdr_2["length"] == len(packet_2_data)
    assert data_2 == packet_2_data
