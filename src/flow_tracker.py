from tls_parser import TLSParser
from http_parser import HTTPParser
from logger import get_logger
from l7_decoders import L7Decoders

logger = get_logger("FlowTracker")

class Flow:
    def __init__(self, flow_key, protocol_name, start_time):
        self.flow_key = flow_key  # canonical 5-tuple (ip_a, port_a, ip_b, port_b, proto)
        self.protocol_name = protocol_name  # e.g., 'TCP', 'UDP'
        self.start_time = start_time
        self.last_active = start_time
        self.packet_count = 0
        self.byte_count = 0
        self.sni = None
        self.app_name = None
        self.state = "ACTIVE"
        self.fin_a_to_b = False
        self.fin_b_to_a = False
        self.packets_buffer = []  # list of (timestamp, raw_packet, original_length)
        
        # Track statistics per direction
        self.bytes_a_to_b = 0
        self.bytes_b_to_a = 0
        self.packets_a_to_b = 0
        self.packets_b_to_a = 0

    def update(self, direction, length, timestamp, raw_data=None):
        self.packet_count += 1
        self.byte_count += length
        self.last_active = timestamp
        
        if direction == 'a_to_b':
            self.bytes_a_to_b += length
            self.packets_a_to_b += 1
        else:
            self.bytes_b_to_a += length
            self.packets_b_to_a += 1

        if raw_data is not None:
            self.packets_buffer.append((timestamp, raw_data, length))

    def update_tcp_state(self, direction, fin, rst):
        if rst:
            self.state = "CLOSED"
        elif fin:
            if direction == 'a_to_b':
                self.fin_a_to_b = True
            else:
                self.fin_b_to_a = True
            if self.fin_a_to_b and self.fin_b_to_a:
                self.state = "CLOSED"

    @property
    def duration(self):
        return max(0.0, self.last_active - self.start_time)


class FlowTracker:
    def __init__(self):
        self.flows = {}  # flow_key -> Flow
        self.expired_flows = {}  # flow_key -> Flow

    @staticmethod
    def get_canonical_key(src_ip, src_port, dst_ip, dst_port, protocol):
        """Generates a canonical bidirectional 5-tuple key."""
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)
        
        # Sort lexicographically so A->B and B->A produce the exact same key
        if endpoint_a <= endpoint_b:
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            return (dst_ip, dst_port, src_ip, src_port, protocol)

    def process_packet(self, src_ip, src_port, dst_ip, dst_port, protocol, length, timestamp, payload=b'', fin=False, rst=False, raw_data=None):
        """
        Updates flow tracking with a new packet.
        Returns the Flow object.
        """
        # Determine protocol name representation
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = f"Proto-{protocol}"

        canonical_key = self.get_canonical_key(src_ip, src_port, dst_ip, dst_port, protocol)
        
        # Determine direction
        if (src_ip, src_port) == (canonical_key[0], canonical_key[1]):
            direction = 'a_to_b'
        else:
            direction = 'b_to_a'

        if canonical_key not in self.flows:
            logger.info(f"New flow detected: {canonical_key[0]}:{canonical_key[1]} <-> {canonical_key[2]}:{canonical_key[3]} | Proto={protocol_name}")
            self.flows[canonical_key] = Flow(canonical_key, protocol_name, timestamp)

        flow = self.flows[canonical_key]
        flow.update(direction, length, timestamp, raw_data)

        if protocol == 6:
            prev_state = flow.state
            flow.update_tcp_state(direction, fin, rst)
            if flow.state != prev_state:
                logger.info(f"Flow state transition: {canonical_key[0]}:{canonical_key[1]} <-> {canonical_key[2]}:{canonical_key[3]} state={flow.state}")

        # Application Classification (SNI/Host Extraction and L7 Decoders)
        if not flow.app_name and payload:
            try:
                # For TCP, check HTTPS and HTTP first
                if protocol == 6:
                    hostname = TLSParser.extract_sni(payload)
                    if hostname:
                        flow.sni = hostname
                        flow.app_name = "HTTPS"
                        logger.info(f"Flow classified: {canonical_key[0]}:{canonical_key[1]} <-> {canonical_key[2]}:{canonical_key[3]} | App=HTTPS | SNI={hostname}")
                    else:
                        host = HTTPParser.extract_host(payload)
                        if host:
                            flow.sni = host
                            flow.app_name = "HTTP"
                            logger.info(f"Flow classified: {canonical_key[0]}:{canonical_key[1]} <-> {canonical_key[2]}:{canonical_key[3]} | App=HTTP | Host={host}")
                
                # If still not classified, check other L7 decoders (SSH, DNS, FTP)
                if not flow.app_name:
                    l7_app = L7Decoders.classify_payload(payload, protocol)
                    if l7_app:
                        flow.app_name = l7_app
                        logger.info(f"Flow classified: {canonical_key[0]}:{canonical_key[1]} <-> {canonical_key[2]}:{canonical_key[3]} | App={l7_app}")
            except Exception as e:
                logger.warning(f"Error classifying application payload: {str(e)}")

        return flow

    def cleanup_expired_flows(self, current_time, idle_timeout=30.0, closed_timeout=5.0):
        """
        Identifies expired or closed flows and moves them to the expired archive.
        """
        expired_keys = []
        for key, flow in self.flows.items():
            if flow.state == "CLOSED":
                if current_time - flow.last_active > closed_timeout:
                    expired_keys.append(key)
                    logger.info(f"Flow expired (TCP closed timeout): {key[0]}:{key[1]} <-> {key[2]}:{key[3]}")
            elif current_time - flow.last_active > idle_timeout:
                expired_keys.append(key)
                logger.info(f"Flow expired (idle timeout): {key[0]}:{key[1]} <-> {key[2]}:{key[3]}")

        for key in expired_keys:
            self.expired_flows[key] = self.flows.pop(key)

