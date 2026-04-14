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
