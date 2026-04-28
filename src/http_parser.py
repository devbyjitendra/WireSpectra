class HTTPParser:
    HTTP_METHODS = {b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT "}

    @staticmethod
    def extract_host(payload: bytes) -> str | None:
        """
        Parses raw TCP payload to identify HTTP requests and extract the Host header.
        Returns the Host value as a string if found, otherwise None.
        """
        if not payload:
            return None

        # Check if the payload starts with a standard HTTP method
        is_http = False
        for method in HTTPParser.HTTP_METHODS:
            if payload.startswith(method):
                is_http = True
                break

        if not is_http:
            return None

        try:
            # Decode the first part of the payload containing headers (typically less than 4KB)
            header_part = payload[:4096].decode('utf-8', errors='ignore')
            lines = header_part.split('\r\n')
            if len(lines) == 1:
                lines = header_part.split('\n')

            for line in lines[1:]: # Skip the request line (first line)
                if not line.strip(): # End of headers
                    break
                if ':' in line:
                    key, val = line.split(':', 1)
                    if key.strip().lower() == 'host':
                        return val.strip()
        except Exception:
            pass

        return None
