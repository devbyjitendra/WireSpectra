class Flow:
    def __init__(self, flow_key, protocol_name, start_time):
        self.flow_key = flow_key  # canonical 5-tuple (ip_a, port_a, ip_b, port_b, proto)
        self.protocol_name = protocol_name  # e.g., 'TCP', 'UDP'
        self.start_time = start_time
        self.last_active = start_time
        self.packet_count = 0
        self.byte_count = 0
        
        # Track statistics per direction
        self.bytes_a_to_b = 0
        self.bytes_b_to_a = 0
        self.packets_a_to_b = 0
        self.packets_b_to_a = 0

    def update(self, direction, length, timestamp):
        self.packet_count += 1
        self.byte_count += length
        self.last_active = timestamp
        
        if direction == 'a_to_b':
            self.bytes_a_to_b += length
            self.packets_a_to_b += 1
        else:
            self.bytes_b_to_a += length
            self.packets_b_to_a += 1

    @property
    def duration(self):
        return max(0.0, self.last_active - self.start_time)


class FlowTracker:
    def __init__(self):
        self.flows = {}  # flow_key -> Flow

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

    def process_packet(self, src_ip, src_port, dst_ip, dst_port, protocol, length, timestamp):
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
            self.flows[canonical_key] = Flow(canonical_key, protocol_name, timestamp)

        flow = self.flows[canonical_key]
        flow.update(direction, length, timestamp)
        return flow
