class L7Decoders:
    @staticmethod
    def detect_ssh(payload: bytes) -> bool:
        """
        Detects SSH protocol based on payload magic bytes.
        SSH clients and servers exchange identification strings starting with 'SSH-'.
        """
        return len(payload) >= 4 and payload.startswith(b"SSH-")

    @staticmethod
    def detect_dns(payload: bytes) -> bool:
        """
        Detects DNS protocol over UDP/TCP based on binary payload headers.
        DNS header is 12 bytes: Transaction ID (2B), Flags (2B), Questions (2B),
        Answer RRs (2B), Authority RRs (2B), Additional RRs (2B).
        """
        if len(payload) < 12:
            return False

        # Unpack counts
        questions = int.from_bytes(payload[4:6], byteorder='big')
        answers = int.from_bytes(payload[6:8], byteorder='big')
        authority = int.from_bytes(payload[8:10], byteorder='big')
        additional = int.from_bytes(payload[10:12], byteorder='big')
        
        # Flags validation
        flags_byte1 = payload[2]
        flags_byte2 = payload[3]
        
        # Opcode is bits 3-6 of flags_byte1. Standard query opcode is 0.
        opcode = (flags_byte1 >> 3) & 0x0f
        # Rcode is bits 0-3 of flags_byte2. Rcode <= 5 are standard valid codes.
        rcode = flags_byte2 & 0x0f
        
        # Standard DNS queries/responses typically have:
        # - 0 < Questions count <= 10 (almost always 1)
        # - Answers/Auth/Additional counts <= 100
        # - Opcode is standard query (0) or status/notify (1-2)
        # - Rcode is valid
        if 0 < questions <= 10 and answers <= 100 and authority <= 100 and additional <= 100:
            if opcode in [0, 1, 2] and rcode <= 5:
                return True
                
        return False

    @staticmethod
    def detect_ftp(payload: bytes) -> bool:
        """
        Detects FTP control channel commands/responses based on text signatures.
        """
        try:
            # FTP control packets are text lines
            text = payload[:30].decode('utf-8', errors='ignore').strip()
            text_upper = text.upper()
            
            # Common FTP client commands
            ftp_commands = [
                "USER ", "PASS ", "PORT ", "PASV ", "SYST ", "FEAT ", 
                "QUIT ", "OPTS ", "PWD ", "TYPE ", "LIST ", "RETR "
            ]
            if any(text_upper.startswith(cmd) for cmd in ftp_commands):
                return True
                
            # FTP server responses: 3 digits followed by space or hyphen (e.g. "220-", "220 ")
            if len(text) >= 4 and text[:3].isdigit() and text[3] in [' ', '-']:
                code = int(text[:3])
                if 100 <= code <= 599:
                    return True
        except Exception:
            pass
            
        return False

    @staticmethod
    def classify_payload(payload: bytes, protocol: int) -> str:
        """
        Returns L7 protocol name if detected, or None.
        """
        if not payload:
            return None

        if L7Decoders.detect_ssh(payload):
            return "SSH"

        if L7Decoders.detect_dns(payload):
            return "DNS"

        if L7Decoders.detect_ftp(payload):
            return "FTP"

        return None
