from collections import defaultdict
from logger import get_logger

logger = get_logger("AnomalyDetector")

class AnomalyDetector:
    def __init__(self, port_threshold: int = 10, syn_threshold: int = 50):
        self.port_threshold = port_threshold
        self.syn_threshold = syn_threshold
        
        # State tracking
        self.src_ports = defaultdict(set)      # src_ip -> set of unique dst_ports
        self.dst_syns = defaultdict(int)       # dst_ip -> SYN packet count
        self.dst_acks = defaultdict(int)       # dst_ip -> ACK packet count
        
        # Prevent duplicate alerts
        self.alerts_triggered = set()
        self.all_alerts = []

    def process_packet(self, src_ip: str, dst_ip: str, dst_port: int, protocol: int, tcp_flags: list = None):
        """
        Processes a packet header and returns alert dict if a new anomaly is triggered.
        """
        # 1. Port Scan Detection (TCP & UDP)
        if protocol in [6, 17] and dst_port > 0:
            self.src_ports[src_ip].add(dst_port)
            
            if len(self.src_ports[src_ip]) > self.port_threshold:
                alert_key = ("PORT_SCAN", src_ip)
                if alert_key not in self.alerts_triggered:
                    self.alerts_triggered.add(alert_key)
                    alert_info = {
                        "type": "PORT_SCAN",
                        "target": src_ip,
                        "details": f"Source IP scanned {len(self.src_ports[src_ip])} unique ports (Threshold: {self.port_threshold})"
                    }
                    self.all_alerts.append(alert_info)
                    logger.warning(f"PORT_SCAN Alert: {alert_info['details']}")
                    return alert_info

        # 2. TCP SYN Flood Detection
        if protocol == 6 and tcp_flags:
            is_syn = "SYN" in tcp_flags
            is_ack = "ACK" in tcp_flags
            
            # Pure SYN packets (handshake start)
            if is_syn and not is_ack:
                self.dst_syns[dst_ip] += 1
            # ACK packets
            elif is_ack:
                self.dst_acks[dst_ip] += 1

            syns = self.dst_syns[dst_ip]
            acks = self.dst_acks[dst_ip]
            
            if syns > self.syn_threshold:
                # Flag if ACK count is extremely low relative to SYN requests
                if acks == 0 or (syns / acks) > 5.0:
                    alert_key = ("SYN_FLOOD", dst_ip)
                    if alert_key not in self.alerts_triggered:
                        self.alerts_triggered.add(alert_key)
                        alert_info = {
                            "type": "SYN_FLOOD",
                            "target": dst_ip,
                            "details": f"Destination IP flooded with {syns} SYNs and only {acks} ACKs (Threshold: {self.syn_threshold})"
                        }
                        self.all_alerts.append(alert_info)
                        logger.warning(f"SYN_FLOOD Alert: {alert_info['details']}")
                        return alert_info
                        
        return None
