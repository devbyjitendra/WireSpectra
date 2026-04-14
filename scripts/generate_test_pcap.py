import struct
import time
import os

def generate_dummy_pcap(filepath, num_packets=10):
    """
    Generates a simple valid PCAP file with dummy Ethernet/IP packets.
    """
    print(f"[*] Generating {num_packets} dummy packets in {filepath}...")
    
    with open(filepath, 'wb') as f:
        # 1. Write Global Header (24 bytes)
        # Magic, VerMaj, VerMin, Zone, Sig, Snap, Network
        global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        f.write(global_header)
        
        # 2. Write Dummy Packets
        for i in range(num_packets):
            # Create a 64-byte dummy packet (just zeroes)
            packet_data = b'\x00' * 64
            
            # Packet Header (16 bytes)
            # ts_sec, ts_usec, incl_len, orig_len
            ts_sec = int(time.time())
            ts_usec = i * 1000
            incl_len = len(packet_data)
            orig_len = len(packet_data)
            
            pkt_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(pkt_header)
            f.write(packet_data)

    print(f"[green]✔[/green] Created {filepath} ({os.path.getsize(filepath)} bytes)")

if __name__ == "__main__":
    # If run directly, create a file in the project root
    output_path = os.path.join(os.path.dirname(__file__), "..", "sample.pcap")
    generate_dummy_pcap(output_path)
