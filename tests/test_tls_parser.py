import sys
import os
import pytest
import struct

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from tls_parser import TLSParser

def test_tls_parser_valid_sni():
    # Build a minimal valid TLS Client Hello payload to extract SNI
    # TLS Record Header (5 bytes): Handshake (0x16), Version (0x0301), Length (98 bytes)
    record_hdr = struct.pack('>BHH', 0x16, 0x0301, 98)
    
    # Handshake Header (4 bytes): Handshake Type Client Hello (0x01), Length (94 bytes)
    handshake_hdr = struct.pack('>B', 0x01) + struct.pack('>I', 94)[1:] # 94 in 3 bytes
    
    # Client Hello (starts at byte 9):
    # Version (2 bytes) = 0x0303
    # Random (32 bytes)
    # Session ID Length (1 byte) = 0
    # Cipher Suites Length (2 bytes) = 2 (1 suite)
    # Cipher Suites (2 bytes) = 0x002f
    # Compression Methods Length (1 byte) = 1
    # Compression Methods (1 byte) = 0
    # Extensions Length (2 bytes) = 21
    
    # SNI Extension:
    # Ext Type (2 bytes) = 0x0000
    # Ext Length (2 bytes) = 17
    # Server Name List Length (2 bytes) = 15
    # Name Type (1 byte) = 0x00
    # Name Length (2 bytes) = 12
    # Name = "example.com"
    sni_ext = struct.pack('>HHHBH', 0x0000, 17, 15, 0x00, 12) + b"example.com"
    
    client_hello = (
        struct.pack('>H', 0x0303) + 
        b'\x00' * 32 + 
        b'\x00' + 
        struct.pack('>H', 2) + 
        struct.pack('>H', 0x002f) + 
        b'\x01\x00' + 
        struct.pack('>H', len(sni_ext)) + 
        sni_ext
    )
    
    payload = record_hdr + handshake_hdr + client_hello
    
    sni = TLSParser.extract_sni(payload)
    assert sni == "example.com"

def test_tls_parser_invalid_handshake():
    # Content type is not handshake (0x15 is Alert instead of 0x16)
    payload = b'\x15' + b'\x00' * 50
    assert TLSParser.extract_sni(payload) is None
