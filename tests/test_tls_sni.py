import sys
import os
import struct

# Add src to path
sys.path.insert(0, os.path.abspath("src"))

from tls_parser import TLSParser

def make_tls_hello(sni: str) -> bytes:
    sni_bytes = sni.encode('utf-8')
    name_len = len(sni_bytes)
    
    # Server name list length = 1 (type) + 2 (len) + name_len = 3 + name_len
    list_len = 3 + name_len
    # SNI extension length = 2 (list_len header) + list_len = 5 + name_len
    sni_ext_len = 2 + list_len
    # Extensions length = 2 (type) + 2 (len) + sni_ext_len = 4 + sni_ext_len = 6 + list_len = 9 + name_len
    ext_len = 4 + sni_ext_len
    
    # Handshake payload size = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_len = 43 + ext_len
    handshake_len = 43 + ext_len
    
    # Record payload size = 4 + handshake_len = 47 + ext_len
    record_len = 4 + handshake_len
    
    payload = bytearray([
        0x16, 0x03, 0x01,
        (record_len >> 8) & 0xFF, record_len & 0xFF  # record length
    ])
    # Client Hello (type=0x01, length=3 bytes)
    payload.extend([0x01, 0x00, (handshake_len >> 8) & 0xFF, handshake_len & 0xFF])
    # TLS 1.2 Version (0x03, 0x03)
    payload.extend([0x03, 0x03])
    # Random 32 bytes
    payload.extend([0xAB] * 32)
    # Session ID length (0), Cipher suites length (2), Cipher suite (0x002f), Compression length (1), Compression method (0)
    payload.extend([0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00])
    # Extensions length (2 bytes)
    payload.extend(struct.pack('!H', ext_len))
    # SNI extension type (0)
    payload.extend([0x00, 0x00])
    # SNI extension length (2 bytes)
    payload.extend(struct.pack('!H', sni_ext_len))
    # Server name list length (2 bytes)
    payload.extend(struct.pack('!H', list_len))
    # Hostname name type (0)
    payload.extend([0x00])
    # Name length (2 bytes)
    payload.extend(struct.pack('!H', name_len))
    # Hostname bytes
    payload.extend(sni_bytes)
    return bytes(payload)

payload = make_tls_hello("youtube.com")
print("Payload length:", len(payload))
print("Payload bytes:", list(payload))
print("Record type:", hex(payload[0]))
print("Record len:", struct.unpack('>H', payload[3:5])[0])
print("Handshake type:", hex(payload[5]))
print("Handshake len:", struct.unpack('>I', b'\x00' + payload[6:9])[0])
extracted = TLSParser.extract_sni(payload)
print(f"Extracted SNI: '{extracted}'")
