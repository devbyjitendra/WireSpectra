import struct

class PcapWriter:
    def __init__(self):
        self.file = None
        self.network = None
        self.snaplen = None

    def open(self, filepath: str, network: int = 1, snaplen: int = 65535):
        """
        Opens a file for writing and writes the 24-byte PCAP global header.
        """
        self.file = open(filepath, 'wb')
        self.network = network
        self.snaplen = snaplen

        # Global Header is 24 bytes:
        # Magic number (0xa1b2c3d4), major version (2), minor version (4),
        # thiszone (0), sigfigs (0), snaplen, network
        global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, network)
        self.file.write(global_header)
        return True

    def write_packet(self, timestamp: float, packet_data: bytes, original_length: int = None):
        """
        Writes a single packet with a 16-byte packet header.
        """
        if not self.file:
            raise ValueError("Writer is not open")

        # Split float timestamp into seconds and microseconds
        ts_sec = int(timestamp)
        ts_usec = int(round((timestamp - ts_sec) * 1_000_000))
        if ts_usec >= 1_000_000:
            ts_sec += 1
            ts_usec -= 1_000_000

        incl_len = len(packet_data)
        if original_length is None:
            original_length = incl_len

        # Limit to snaplen
        if incl_len > self.snaplen:
            packet_data = packet_data[:self.snaplen]
            incl_len = self.snaplen

        # Packet Header: ts_sec, ts_usec, incl_len, orig_len
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, original_length)
        self.file.write(pkt_header)
        self.file.write(packet_data)

    def close(self):
        if self.file:
            self.file.close()
            self.file = None
