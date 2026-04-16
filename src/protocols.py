import struct

class EthernetFrame:
    def __init__(self, raw_data: bytes):
        """
        Parses an Ethernet (IEEE 802.3) frame header.
        Ethernet Header is 14 bytes:
        - Destination MAC (6 bytes)
        - Source MAC (6 bytes)
        - EtherType (2 bytes)
        """
        if len(raw_data) < 14:
            raise ValueError("Data too short for Ethernet frame")
        
        self.raw_data = raw_data
        self.dst_mac_raw = raw_data[0:6]
        self.src_mac_raw = raw_data[6:12]
        self.ethertype = struct.unpack('>H', raw_data[12:14])[0]
        self.payload = raw_data[14:]

    @staticmethod
    def format_mac(mac_bytes: bytes) -> str:
        """Formats 6 bytes MAC address into xx:xx:xx:xx:xx:xx format."""
        return ":".join(f"{b:02x}" for b in mac_bytes)

    @property
    def dst_mac(self) -> str:
        return self.format_mac(self.dst_mac_raw)

    @property
    def src_mac(self) -> str:
        return self.format_mac(self.src_mac_raw)

    def get_ethertype_name(self) -> str:
        """Returns name representation of the EtherType."""
        names = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86dd: "IPv6",
        }
        return names.get(self.ethertype, f"0x{self.ethertype:04x}")


class IPv4Packet:
    def __init__(self, raw_data: bytes):
        """
        Parses an IPv4 header.
        IPv4 minimum header length is 20 bytes.
        """
        if len(raw_data) < 20:
            raise ValueError("Data too short for IPv4 packet")
        
        self.raw_data = raw_data
        
        # Parse first byte (Version and IHL)
        version_ihl = raw_data[0]
        self.version = version_ihl >> 4
        self.ihl = (version_ihl & 0x0F) * 4 # Header length in bytes
        
        if len(raw_data) < self.ihl:
            raise ValueError("Data shorter than IPv4 header size (IHL)")
            
        self.tos = raw_data[1]
        self.total_length = struct.unpack('>H', raw_data[2:4])[0]
        self.identification = struct.unpack('>H', raw_data[4:6])[0]
        
        flags_fragment = struct.unpack('>H', raw_data[6:8])[0]
        self.flags = flags_fragment >> 13
        self.fragment_offset = flags_fragment & 0x1FFF
        
        self.ttl = raw_data[8]
        self.protocol = raw_data[9]
        self.checksum = struct.unpack('>H', raw_data[10:12])[0]
        
        self.src_ip_raw = raw_data[12:16]
        self.dst_ip_raw = raw_data[16:20]
        
        # Payload up to total_length
        self.payload = raw_data[self.ihl:self.total_length]

    @staticmethod
    def format_ip(ip_bytes: bytes) -> str:
        """Formats 4 bytes IP address into xxx.xxx.xxx.xxx format."""
        return ".".join(str(b) for b in ip_bytes)

    @property
    def src_ip(self) -> str:
        return self.format_ip(self.src_ip_raw)

    @property
    def dst_ip(self) -> str:
        return self.format_ip(self.dst_ip_raw)

    def get_protocol_name(self) -> str:
        """Returns protocol name representation."""
        protocols = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
        }
        return protocols.get(self.protocol, f"IP-proto-{self.protocol}")


class TCPPacket:
    def __init__(self, raw_data: bytes):
        """
        Parses a TCP header.
        TCP minimum header length is 20 bytes.
        """
        if len(raw_data) < 20:
            raise ValueError("Data too short for TCP packet")

        self.raw_data = raw_data
        self.src_port = struct.unpack('>H', raw_data[0:2])[0]
        self.dst_port = struct.unpack('>H', raw_data[2:4])[0]
        self.seq_num = struct.unpack('>I', raw_data[4:8])[0]
        self.ack_num = struct.unpack('>I', raw_data[8:12])[0]
        
        # Data Offset is high 4 bits of the 12th byte
        data_offset_byte = raw_data[12]
        self.data_offset = (data_offset_byte >> 4) * 4 # Header size in bytes
        
        if len(raw_data) < self.data_offset:
            raise ValueError("Data shorter than TCP header size (data offset)")

        # Flags are the lower 6 bits of the 13th byte
        self.flags_byte = raw_data[13]
        
        # Common Flags
        self.fin = bool(self.flags_byte & 0x01)
        self.syn = bool(self.flags_byte & 0x02)
        self.rst = bool(self.flags_byte & 0x04)
        self.psh = bool(self.flags_byte & 0x08)
        self.ack = bool(self.flags_byte & 0x10)
        self.urg = bool(self.flags_byte & 0x20)
        
        self.window_size = struct.unpack('>H', raw_data[14:16])[0]
        self.checksum = struct.unpack('>H', raw_data[16:18])[0]
        self.urgent_pointer = struct.unpack('>H', raw_data[18:20])[0]
        
        self.payload = raw_data[self.data_offset:]

    def get_flags_str(self) -> str:
        """Returns active flags as a string, e.g., 'SYN, ACK'."""
        flags = []
        if self.urg: flags.append("URG")
        if self.ack: flags.append("ACK")
        if self.psh: flags.append("PSH")
        if self.rst: flags.append("RST")
        if self.syn: flags.append("SYN")
        if self.fin: flags.append("FIN")
        return ", ".join(flags)


class UDPPacket:
    def __init__(self, raw_data: bytes):
        """
        Parses a UDP header.
        UDP header length is exactly 8 bytes.
        """
        if len(raw_data) < 8:
            raise ValueError("Data too short for UDP packet")

        self.raw_data = raw_data
        self.src_port = struct.unpack('>H', raw_data[0:2])[0]
        self.dst_port = struct.unpack('>H', raw_data[2:4])[0]
        self.length = struct.unpack('>H', raw_data[4:6])[0]
        self.checksum = struct.unpack('>H', raw_data[6:8])[0]
        
        self.payload = raw_data[8:self.length] if self.length >= 8 else raw_data[8:]


