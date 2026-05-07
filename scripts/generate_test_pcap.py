"""
generate_test_pcap.py — WireSpectra Test PCAP Generator
Produces a realistic multi-flow PCAP with HTTP, DNS, TLS (HTTPS), and SSH traffic.
Usage:
    python scripts/generate_test_pcap.py               # saves to sample.pcap
    python scripts/generate_test_pcap.py my_test.pcap  # saves to my_test.pcap
"""

import struct
import time
import os
import sys


# ── Binary packet builders ──────────────────────────────────────────────────

def eth_header(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    """14-byte Ethernet II header."""
    return struct.pack('!6s6sH', dst_mac, src_mac, ethertype)


def ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int,
              pkt_id: int = 1) -> bytes:
    """20-byte IPv4 header (no options, checksum left as 0)."""
    total_len = 20 + payload_len
    src = bytes(int(x) for x in src_ip.split('.'))
    dst = bytes(int(x) for x in dst_ip.split('.'))
    return struct.pack('!BBHHHBBH4s4s',
                       0x45, 0, total_len, pkt_id, 0, 64,
                       protocol, 0, src, dst)


def tcp_header(src_port: int, dst_port: int, seq: int, ack: int,
               flags: int, payload_len: int) -> bytes:
    """20-byte TCP header. flags: e.g. 0x02=SYN, 0x18=PSH|ACK, 0x11=FIN|ACK."""
    window = 64240
    # data offset = 5 (20 bytes / 4), packed into top nibble of a byte
    data_offset = (5 << 4)
    return struct.pack('!HHIIBBHHH',
                       src_port, dst_port, seq, ack,
                       data_offset, flags, window, 0, 0)


def udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    """8-byte UDP header."""
    length = 8 + payload_len
    return struct.pack('!HHHH', src_port, dst_port, length, 0)


def pcap_global_header() -> bytes:
    """24-byte PCAP global header (little-endian, Ethernet link layer)."""
    return struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


def pcap_packet_header(ts: float, data_len: int) -> bytes:
    """16-byte PCAP per-packet header."""
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack('<IIII', ts_sec, ts_usec, data_len, data_len)


# ── MAC addresses ───────────────────────────────────────────────────────────

CLIENT_MAC = b'\x00\x0c\x29\x4f\x8b\x35'
ROUTER_MAC = b'\x00\x50\x56\xc0\x00\x01'


def make_packet(src_ip, dst_ip, src_port, dst_port, protocol,
                tcp_flags, payload=b'', pkt_id=1) -> bytes:
    """Build a full Ethernet+IP+TCP/UDP packet."""
    if protocol == 6:   # TCP
        l4 = tcp_header(src_port, dst_port, pkt_id * 100, 0, tcp_flags, len(payload))
    else:               # UDP
        l4 = udp_header(src_port, dst_port, len(payload))

    ip = ip_header(src_ip, dst_ip, protocol, len(l4) + len(payload), pkt_id)
    eth = eth_header(CLIENT_MAC, ROUTER_MAC)
    return eth + ip + l4 + payload


# ── Traffic payloads ────────────────────────────────────────────────────────

HTTP_REQUEST = (
    b"GET / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: WireSpectra/1.0\r\n"
    b"Accept: */*\r\n\r\n"
)

HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 13\r\n\r\n"
    b"Hello, World!"
)

# Minimal TLS 1.2 ClientHello with SNI=github.com
TLS_CLIENT_HELLO = bytes([
    0x16, 0x03, 0x01, 0x00, 0x5a,   # TLS record: Handshake, TLS 1.0, length=90
    0x01, 0x00, 0x00, 0x56,          # ClientHello, length=86
    0x03, 0x03,                       # TLS 1.2 version
] + [0xAB] * 32 +                    # 32 random bytes
[
    0x00,                             # session_id length = 0
    0x00, 0x02, 0x00, 0x2f,          # cipher suites: 1 suite (TLS_RSA_WITH_AES_128_CBC_SHA)
    0x01, 0x00,                       # compression: null
    0x00, 0x1b,                       # extensions length = 27
    # SNI extension
    0x00, 0x00,                       # extension type: server_name (0)
    0x00, 0x13,                       # extension length = 19
    0x00, 0x11,                       # server_name_list length = 17
    0x00,                             # name_type: host_name
    0x00, 0x0e,                       # name length = 14
    # "github.com" (10 bytes) — but we write 14 bytes "www.github.com"
    ord('w'), ord('w'), ord('w'), ord('.'),
    ord('g'), ord('i'), ord('t'), ord('h'),
    ord('u'), ord('b'), ord('.'), ord('c'),
    ord('o'), ord('m'),
])

# Minimal DNS query for "google.com" (A record)
DNS_QUERY = bytes([
    0x12, 0x34,       # Transaction ID
    0x01, 0x00,       # Flags: standard query
    0x00, 0x01,       # Questions: 1
    0x00, 0x00,       # Answers: 0
    0x00, 0x00,       # Authority: 0
    0x00, 0x00,       # Additional: 0
    # QNAME: google.com
    0x06, ord('g'), ord('o'), ord('o'), ord('g'), ord('l'), ord('e'),
    0x03, ord('c'), ord('o'), ord('m'),
    0x00,             # end of name
    0x00, 0x01,       # QTYPE: A
    0x00, 0x01,       # QCLASS: IN
])

# SSH banner (first bytes of a real SSH handshake)
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"


# ── Main generator ──────────────────────────────────────────────────────────

def generate_pcap(filepath: str):
    print(f"[*] Generating realistic multi-flow PCAP -> {filepath}")
    base_ts = time.time()

    packets = []  # list of (timestamp, raw_bytes)

    def add(ts_offset, pkt):
        packets.append((base_ts + ts_offset, pkt))

    # ── Flow 1: HTTP (port 80) ──────────────────────────────────────────────
    # SYN
    add(0.000, make_packet("192.168.1.10", "93.184.216.34",
                            54321, 80, 6, 0x02, b'', pkt_id=1))
    # SYN-ACK (server reply, swapped src/dst)
    add(0.010, make_packet("93.184.216.34", "192.168.1.10",
                            80, 54321, 6, 0x12, b'', pkt_id=100))
    # ACK
    add(0.011, make_packet("192.168.1.10", "93.184.216.34",
                            54321, 80, 6, 0x10, b'', pkt_id=2))
    # HTTP GET (PSH+ACK)
    add(0.012, make_packet("192.168.1.10", "93.184.216.34",
                            54321, 80, 6, 0x18, HTTP_REQUEST, pkt_id=3))
    # HTTP 200 response
    add(0.080, make_packet("93.184.216.34", "192.168.1.10",
                            80, 54321, 6, 0x18, HTTP_RESPONSE, pkt_id=101))
    # FIN+ACK (client)
    add(0.090, make_packet("192.168.1.10", "93.184.216.34",
                            54321, 80, 6, 0x11, b'', pkt_id=4))

    # ── Flow 2: DNS (port 53 UDP) ───────────────────────────────────────────
    add(0.100, make_packet("192.168.1.10", "8.8.8.8",
                            55000, 53, 17, 0, DNS_QUERY, pkt_id=10))

    # ── Flow 3: HTTPS/TLS (port 443) ───────────────────────────────────────
    # SYN
    add(0.200, make_packet("192.168.1.10", "140.82.114.4",
                            60000, 443, 6, 0x02, b'', pkt_id=20))
    # SYN-ACK
    add(0.210, make_packet("140.82.114.4", "192.168.1.10",
                            443, 60000, 6, 0x12, b'', pkt_id=200))
    # ACK
    add(0.211, make_packet("192.168.1.10", "140.82.114.4",
                            60000, 443, 6, 0x10, b'', pkt_id=21))
    # TLS ClientHello with SNI
    add(0.212, make_packet("192.168.1.10", "140.82.114.4",
                            60000, 443, 6, 0x18, TLS_CLIENT_HELLO, pkt_id=22))
    # More HTTPS data
    for i in range(5):
        add(0.300 + i * 0.05, make_packet("192.168.1.10", "140.82.114.4",
                                           60000, 443, 6, 0x18, b'\x17\x03\x03' + b'\xAB' * 50,
                                           pkt_id=23 + i))

    # ── Flow 4: SSH (port 22) ───────────────────────────────────────────────
    add(0.600, make_packet("192.168.1.10", "10.0.0.5",
                            40000, 22, 6, 0x02, b'', pkt_id=40))
    add(0.610, make_packet("10.0.0.5", "192.168.1.10",
                            22, 40000, 6, 0x12, b'', pkt_id=400))
    add(0.611, make_packet("192.168.1.10", "10.0.0.5",
                            40000, 22, 6, 0x10, b'', pkt_id=41))
    # SSH banner from server
    add(0.620, make_packet("10.0.0.5", "192.168.1.10",
                            22, 40000, 6, 0x18, SSH_BANNER, pkt_id=401))
    # SSH data packets
    for i in range(4):
        add(0.700 + i * 0.1, make_packet("192.168.1.10", "10.0.0.5",
                                          40000, 22, 6, 0x18, b'\x00' * 64,
                                          pkt_id=42 + i))

    # ── Write PCAP file ─────────────────────────────────────────────────────
    with open(filepath, 'wb') as f:
        f.write(pcap_global_header())
        for ts, pkt in packets:
            f.write(pcap_packet_header(ts, len(pkt)))
            f.write(pkt)

    total_size = os.path.getsize(filepath)
    print(f"[OK] Written {len(packets)} packets across 4 flows to: {filepath}")
    print(f"     Flows: HTTP (port 80) | DNS (UDP 53) | HTTPS/TLS (port 443) | SSH (port 22)")
    print(f"     File size: {total_size} bytes")
    print(f"\nRun with:")
    print(f"  python src/main.py {filepath} --report")
    print(f"  python src/main.py {filepath} --report --export-json report.json")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "sample.pcap"
    )
    generate_pcap(os.path.normpath(output))
