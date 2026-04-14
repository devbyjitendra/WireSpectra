import struct
import os

class PcapReader:
    def __init__(self):
        self.file = None
        self.magic_number = None
        self.version_major = None
        self.version_minor = None
        self.snaplen = None
        self.network = None

    def open(self, filepath: str):
        """
        Opens a PCAP file and parses the 24-byte global header.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        self.file = open(filepath, 'rb')
        
        # PCAP Global Header is exactly 24 bytes
        header_data = self.file.read(24)
        if len(header_data) < 24:
            self.file.close()
            raise ValueError("Invalid PCAP file: Global header too short")

        # Unpack the 24 bytes using struct
        # I: uint32, H: uint16
        # < for little-endian (standard PCAP)
        (
            self.magic_number,
            self.version_major,
            self.version_minor,
            self.thiszone,     # GMT to local correction (ignored)
            self.sigfigs,      # Accuracy of timestamps (ignored)
            self.snaplen,      # Max length of captured packets
            self.network       # Data link type (1 = Ethernet)
        ) = struct.unpack('<IHHIIII', header_data)

        # Verify magic number (0xa1b2c3d4 is standard PCAP)
        if self.magic_number != 0xa1b2c3d4:
            # Check for big-endian version
            if self.magic_number == 0xd4c3b2a1:
                raise ValueError("Big-endian PCAP files not supported yet")
            raise ValueError(f"Not a valid PCAP file. Magic: {hex(self.magic_number)}")

        return True

    def __iter__(self):
        return self

    def __next__(self):
        """
        Reads the next packet from the file. 
        Returns (header_dict, raw_data_bytes).
        """
        if not self.file:
            raise StopIteration

        # PCAP Packet Header is exactly 16 bytes
        pkt_header = self.file.read(16)
        if len(pkt_header) < 16:
            raise StopIteration

        # Unpack Packet Header: 4x uint32
        # ts_sec, ts_usec, incl_len, orig_len
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)

        # Read the actual packet data
        packet_data = self.file.read(incl_len)
        
        header_info = {
            "timestamp": ts_sec + (ts_usec / 1_000_000),
            "length": incl_len,
            "original_length": orig_len
        }

        return header_info, packet_data

    def close(self):
        if self.file:
            self.file.close()

    def __repr__(self):
        return (f"PcapReader(Version={self.version_major}.{self.version_minor}, "
                f"Snaplen={self.snaplen}, Network={self.network})")
