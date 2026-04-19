import struct

class TLSParser:
    @staticmethod
    def extract_sni(payload: bytes) -> str | None:
        """
        Parses a TLS Client Hello handshake payload and extracts the SNI (Server Name Indication).
        Returns the hostname string if found, otherwise None.
        """
        # Minimum size for a TLS Record header + Handshake header + Client Hello elements is around 45 bytes
        if len(payload) < 45:
            return None

        # 1. Verify TLS Record Content Type is Handshake (0x16)
        if payload[0] != 0x16:
            return None

        # 2. Extract TLS Record length (from byte 3-5)
        # payload[1:3] is version (e.g. 0x0301)
        record_len = struct.unpack('>H', payload[3:5])[0]
        
        # Ensure we have the full record in payload
        if len(payload) < 5 + record_len:
            return None

        # 3. Handshake type must be Client Hello (0x01)
        # The handshake payload starts at byte 5
        if payload[5] != 0x01:
            return None

        # We start parsing the Client Hello starting at byte 9 (Version)
        idx = 9
        if idx + 34 > len(payload):
            return None
        
        # Skip Version (2 bytes) and Random (32 bytes)
        idx += 34
        
        # Session ID Length (1 byte)
        if idx >= len(payload): return None
        session_id_len = payload[idx]
        idx += 1 + session_id_len
        
        # Cipher Suites Length (2 bytes)
        if idx + 2 > len(payload): return None
        cipher_suites_len = struct.unpack('>H', payload[idx:idx+2])[0]
        idx += 2 + cipher_suites_len
        
        # Compression Methods Length (1 byte)
        if idx >= len(payload): return None
        compression_len = payload[idx]
        idx += 1 + compression_len
        
        # Extensions Length (2 bytes)
        if idx + 2 > len(payload): return None
        extensions_len = struct.unpack('>H', payload[idx:idx+2])[0]
        idx += 2
        
        target_end = idx + extensions_len
        if target_end > len(payload):
            return None
            
        # Parse Extensions
        while idx + 4 <= target_end:
            ext_type = struct.unpack('>H', payload[idx:idx+2])[0]
            ext_len = struct.unpack('>H', payload[idx+2:idx+4])[0]
            idx += 4
            
            if idx + ext_len > target_end:
                break
                
            # Extension Type 0x0000 is Server Name (SNI)
            if ext_type == 0x0000:
                sni_idx = idx
                if sni_idx + 2 > idx + ext_len:
                    break
                
                # Server Name List Length (2 bytes)
                list_len = struct.unpack('>H', payload[sni_idx:sni_idx+2])[0]
                sni_idx += 2
                
                if sni_idx + list_len > idx + ext_len:
                    break
                    
                # Parse Server Name List
                while sni_idx + 3 <= idx + ext_len:
                    name_type = payload[sni_idx]
                    name_len = struct.unpack('>H', payload[sni_idx+1:sni_idx+3])[0]
                    sni_idx += 3
                    
                    if sni_idx + name_len > idx + ext_len:
                        break
                        
                    # Name Type 0x00 is Hostname
                    if name_type == 0x00:
                        try:
                            hostname = payload[sni_idx:sni_idx+name_len].decode('utf-8', errors='ignore')
                            return hostname
                        except Exception:
                            pass
                    sni_idx += name_len
            
            idx += ext_len
            
        return None
