import os
import sys
import time
import random
import threading
from typing import Dict, Any, List
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Add src to python path if not already there
sys.path.insert(0, os.path.dirname(__file__))

# Import DPI engine components
from protocols import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
from flow_tracker import FlowTracker
from anomaly_detector import AnomalyDetector
from rules_engine import RulesEngine
from pcap_writer import PcapWriter
from reporter import DPIReportGenerator

app = FastAPI(title="WireSpectra DPI Live Simulator")

# Enable CORS for Vercel/localhost frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared in-memory state
state_lock = threading.Lock()
live_report = {
    "summary": {
        "total_packets": 0,
        "total_bytes": 0,
        "duration_sec": 0.0,
        "avg_pps": 0.0,
        "avg_kbps": 0.0
    },
    "protocols": {},
    "applications": {},
    "alerts": [],
    "flows": []
}

# PCAP file configurations
PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "live.pcap")
pcap_writer = None
first_packet_ts = None
last_packet_ts = None
packet_count = 0
total_bytes = 0

# DPI instances
tracker = FlowTracker()
anomaly_detector = AnomalyDetector()
rules_engine = RulesEngine()

# Pre-defined mock targets & data generators for generating random live packets
CLIENT_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.20"]
WEBSITES = [
    ("93.184.216.34", 80, "HTTP", "example.com"),
    ("140.82.114.4", 443, "HTTPS", "www.github.com"),
    ("142.250.190.46", 443, "HTTPS", "www.google.com"),
    ("10.0.0.5", 22, "SSH", ""),
    ("8.8.8.8", 53, "DNS", "dns.google"),
    ("192.168.1.254", 21, "FTP", ""),
    ("172.217.16.142", 443, "HTTPS", "youtube.com"),
    ("31.13.71.36", 443, "HTTPS", "facebook.com"),
    ("185.60.218.35", 443, "HTTPS", "netflix.com"),
]

# Helper functions to build packets (similar to scripts/generate_test_pcap.py)
import struct

CLIENT_MAC = b'\x00\x0c\x29\x4f\x8b\x35'
ROUTER_MAC = b'\x00\x50\x56\xc0\x00\x01'

def eth_header(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    return struct.pack('!6s6sH', dst_mac, src_mac, ethertype)

def ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int, pkt_id: int = 1) -> bytes:
    total_len = 20 + payload_len
    src = bytes(int(x) for x in src_ip.split('.'))
    dst = bytes(int(x) for x in dst_ip.split('.'))
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, pkt_id, 0, 64, protocol, 0, src, dst)

def tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload_len: int) -> bytes:
    window = 64240
    data_offset = (5 << 4)
    return struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flags, window, 0, 0)

def udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    return struct.pack('!HHHH', src_port, dst_port, 8 + payload_len, 0)

def make_packet(src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, payload=b'', pkt_id=1) -> bytes:
    if protocol == 6:   # TCP
        l4 = tcp_header(src_port, dst_port, pkt_id * 100, 0, tcp_flags, len(payload))
    else:               # UDP
        l4 = udp_header(src_port, dst_port, len(payload))
    ip = ip_header(src_ip, dst_ip, protocol, len(l4) + len(payload), pkt_id)
    eth = eth_header(CLIENT_MAC, ROUTER_MAC)
    return eth + ip + l4 + payload

# Payloads
HTTP_REQUEST = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\nHello World!"
TLS_CLIENT_HELLO_TEMPLATE = [
    0x16, 0x03, 0x01, 0x00, 0x5a,
    0x01, 0x00, 0x00, 0x56,
    0x03, 0x03,
] + [0xAB] * 32 + [
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    0x00, 0x1b,
    0x00, 0x00,
    0x00, 0x13,
    0x00, 0x11,
    0x00,
]

def make_tls_hello(sni: str) -> bytes:
    sni_bytes = sni.encode('utf-8')
    name_len = len(sni_bytes)
    
    # Server name list length = 1 (type) + 2 (len) + name_len = 3 + name_len
    list_len = 3 + name_len
    # SNI extension length = 2 (list_len header) + list_len = 5 + name_len
    sni_ext_len = 2 + list_len
    # Extensions length = 2 (type) + 2 (len) + sni_ext_len = 6 + list_len = 9 + name_len
    ext_len = 4 + sni_ext_len
    
    # Handshake payload size = 43 + ext_len
    handshake_len = 43 + ext_len
    
    # Record payload size = 47 + ext_len
    record_len = 47 + ext_len
    
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

DNS_QUERY = bytes([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, ord('g'), ord('o'), ord('o'), ord('g'), ord('l'), ord('e'),
    0x03, ord('c'), ord('o'), ord('m'), 0x00, 0x00, 0x01, 0x00, 0x01
])
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

# Active flow simulator context tracker
active_sim_flows = {}

def process_one_packet(raw_pkt: bytes, ts: float):
    global packet_count, total_bytes, first_packet_ts, last_packet_ts
    
    packet_count += 1
    total_bytes += len(raw_pkt)
    if first_packet_ts is None:
        first_packet_ts = ts
    last_packet_ts = ts

    # Write packet to PCAP file
    if pcap_writer:
        pcap_writer.write_packet(ts, raw_pkt, len(raw_pkt))

    # DPI engine analysis (similar to main.py batch/loop)
    try:
        eth_frame = EthernetFrame(raw_pkt)
        if eth_frame.ethertype == 0x0800:  # IPv4
            ip_pkt = IPv4Packet(eth_frame.payload)
            src_ip = ip_pkt.src_ip
            dst_ip = ip_pkt.dst_ip
            protocol = ip_pkt.protocol
            
            src_port = 0
            dst_port = 0
            tcp_payload = b''
            fin_flag = False
            rst_flag = False
            pkt_payload = b''
            tcp_flags = []
            
            if protocol == 6:  # TCP
                tcp_pkt = TCPPacket(ip_pkt.payload)
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
                tcp_payload = tcp_pkt.payload
                pkt_payload = tcp_payload
                fin_flag = tcp_pkt.fin
                rst_flag = tcp_pkt.rst
                if tcp_pkt.syn: tcp_flags.append("SYN")
                if tcp_pkt.ack: tcp_flags.append("ACK")
                if tcp_pkt.fin: tcp_flags.append("FIN")
                if tcp_pkt.rst: tcp_flags.append("RST")
                if tcp_pkt.psh: tcp_flags.append("PSH")
            elif protocol == 17:  # UDP
                udp_pkt = UDPPacket(ip_pkt.payload)
                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port
                pkt_payload = udp_pkt.payload
            
            # Feed to flow tracker
            flow = tracker.process_packet(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                length=len(raw_pkt),
                timestamp=ts,
                payload=tcp_payload if protocol == 6 else pkt_payload,
                fin=fin_flag,
                rst=rst_flag,
                raw_data=raw_pkt
            )
            
            # Feed to rules engine
            matched_rule = rules_engine.evaluate_flow(flow, payload=pkt_payload)
            if matched_rule:
                if matched_rule.action == "BLOCK":
                    flow.state = "BLOCKED"
                flow.matched_rule = matched_rule
            
            # Feed to anomaly detector
            anomaly_detector.process_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                tcp_flags=tcp_flags
            )
            
    except Exception as e:
        # Catch and log decoder issues
        print(f"[Decoder Exception]: {str(e)}")


def live_generator_loop():
    global pcap_writer, tracker, anomaly_detector, first_packet_ts, last_packet_ts, packet_count, total_bytes
    
    print("[*] Starting live packet simulator background thread...")
    # Initialize PCAP writer
    reset_live_state()

    flow_sequence_ids = {}

    while True:
        try:
            time.sleep(0.4) # Generate packet(s) every 0.4s

            with state_lock:
                ts = time.time()
                
                # Pick a random client and destination
                client = random.choice(CLIENT_IPS)
                dst_ip, dst_port, proto_name, sni = random.choice(WEBSITES)
                
                # Assign a client port if not exists or reuse
                flow_key = (client, dst_ip, proto_name)
                if flow_key not in flow_sequence_ids:
                    flow_sequence_ids[flow_key] = {
                        "src_port": random.randint(49152, 65535),
                        "seq_num": 1,
                        "state": "SYN"
                    }
                
                flow_info = flow_sequence_ids[flow_key]
                src_port = flow_info["src_port"]
                pkt_id = flow_info["seq_num"]
                state = flow_info["state"]

                # Generate realistic packet handshake/payload
                raw_pkt = b''
                if proto_name == "DNS":
                    # UDP simple DNS Query
                    raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 17, 0, DNS_QUERY, pkt_id)
                    flow_info["seq_num"] += 1
                    # Swap immediately to closed simulation
                    del flow_sequence_ids[flow_key]
                elif proto_name == "HTTP":
                    if state == "SYN":
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x02, b'', pkt_id)
                        flow_info["state"] = "DATA"
                    elif state == "DATA":
                        # HTTP GET Request
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x18, HTTP_REQUEST, pkt_id)
                        flow_info["state"] = "RESPONSE"
                    elif state == "RESPONSE":
                        # HTTP 200 Response (Server to Client)
                        raw_pkt = make_packet(dst_ip, client, dst_port, src_port, 6, 0x18, HTTP_RESPONSE, pkt_id)
                        flow_info["state"] = "FIN"
                    elif state == "FIN":
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x11, b'', pkt_id)
                        process_one_packet(raw_pkt, ts)
                        server_fin = make_packet(dst_ip, client, dst_port, src_port, 6, 0x11, b'', pkt_id)
                        process_one_packet(server_fin, ts + 0.01)
                        raw_pkt = None
                        del flow_sequence_ids[flow_key]
                elif proto_name == "HTTPS":
                    if state == "SYN":
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x02, b'', pkt_id)
                        flow_info["state"] = "HELLO"
                    elif state == "HELLO":
                        # TLS ClientHello
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x18, make_tls_hello(sni), pkt_id)
                        flow_info["state"] = "DATA"
                    elif state == "DATA":
                        # Encrypted Application Data
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x18, b'\x17\x03\x03' + os.urandom(128), pkt_id)
                        # Randomly terminate or keep sending data
                        if random.random() > 0.6:
                            flow_info["state"] = "FIN"
                        else:
                            flow_info["seq_num"] += 1
                    elif state == "FIN":
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x11, b'', pkt_id)
                        process_one_packet(raw_pkt, ts)
                        server_fin = make_packet(dst_ip, client, dst_port, src_port, 6, 0x11, b'', pkt_id)
                        process_one_packet(server_fin, ts + 0.01)
                        raw_pkt = None
                        del flow_sequence_ids[flow_key]
                elif proto_name == "SSH":
                    if state == "SYN":
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x02, b'', pkt_id)
                        flow_info["state"] = "BANNER"
                    elif state == "BANNER":
                        raw_pkt = make_packet(dst_ip, client, dst_port, src_port, 6, 0x18, SSH_BANNER, pkt_id)
                        flow_info["state"] = "DATA"
                    elif state == "DATA":
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x18, os.urandom(64), pkt_id)
                        if random.random() > 0.8:
                            flow_info["state"] = "FIN"
                        else:
                            flow_info["seq_num"] += 1
                    elif state == "FIN":
                        raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x11, b'', pkt_id)
                        process_one_packet(raw_pkt, ts)
                        server_fin = make_packet(dst_ip, client, dst_port, src_port, 6, 0x11, b'', pkt_id)
                        process_one_packet(server_fin, ts + 0.01)
                        raw_pkt = None
                        del flow_sequence_ids[flow_key]
                else: # FTP or general TCP
                    raw_pkt = make_packet(client, dst_ip, src_port, dst_port, 6, 0x02, b'', pkt_id)
                    del flow_sequence_ids[flow_key]

                if raw_pkt:
                    process_one_packet(raw_pkt, ts)

                # Periodically clean up expired flows (idle > 15 seconds, closed > 3 seconds)
                tracker.cleanup_expired_flows(ts, idle_timeout=15.0, closed_timeout=3.0)

                # Occasionally generate a Port Scan anomaly to show off alerts!
                if random.random() < 0.08:
                    scanner_ip = f"192.168.1.{random.randint(100, 200)}"
                    victim_ip = "10.0.0.9"
                    for _ in range(12): # trigger threshold (10)
                        scan_port = random.randint(1, 1024)
                        scan_pkt = make_packet(scanner_ip, victim_ip, random.randint(40000, 50000), scan_port, 6, 0x02, b'', 1)
                        process_one_packet(scan_pkt, ts)

                # Periodically update the JSON report state
                update_live_report()

        except Exception as e:
            print(f"[Error in live generator]: {str(e)}")
            time.sleep(2)

def update_live_report():
    global live_report, tracker, anomaly_detector, first_packet_ts, last_packet_ts, packet_count, total_bytes
    
    all_flows = list(tracker.flows.values()) + list(tracker.expired_flows.values())
    duration = (last_packet_ts - first_packet_ts) if (last_packet_ts and first_packet_ts) else 0.0
    
    throughput = DPIReportGenerator.generate_throughput_summary(packet_count, total_bytes, duration)
    dist = DPIReportGenerator.generate_distribution_report(all_flows)
    
    flows_list = []
    for idx, flow in enumerate(all_flows, 1):
        ip_a, port_a, ip_b, port_b, proto = flow.flow_key
        dur = flow.duration
        pkts_per_sec = flow.packet_count / dur if dur > 0 else 0.0
        bytes_per_sec = flow.byte_count / dur if dur > 0 else 0.0
        
        status_str = "ACTIVE"
        if flow.state == "BLOCKED":
            status_str = "BLOCKED"
        elif flow.state == "CLOSED":
            status_str = "CLOSED"
        elif flow.state == "EXPIRED":
            status_str = "EXPIRED"
            
        flows_list.append({
            "flow_id": idx,
            "protocol": flow.protocol_name,
            "app_name": flow.app_name or "Unclassified",
            "sni": flow.sni or "",
            "src_ip": ip_a,
            "src_port": port_a,
            "dst_ip": ip_b,
            "dst_port": port_b,
            "packets": flow.packet_count,
            "bytes": flow.byte_count,
            "duration_sec": round(dur, 4),
            "packets_per_sec": round(pkts_per_sec, 2),
            "bytes_per_sec": round(bytes_per_sec, 2),
            "status": status_str
        })

    live_report = {
        "summary": {
            "total_packets": packet_count,
            "total_bytes": total_bytes,
            "duration_sec": round(duration, 4),
            "avg_pps": round(throughput["avg_pps"], 2),
            "avg_kbps": round(throughput["avg_kbps"], 2)
        },
        "protocols": dist["protocols"],
        "applications": dist["applications"],
        "alerts": anomaly_detector.all_alerts,
        "flows": flows_list
    }

def reset_live_state():
    global pcap_writer, tracker, anomaly_detector, first_packet_ts, last_packet_ts, packet_count, total_bytes, live_report
    
    if pcap_writer:
        try:
            pcap_writer.close()
        except Exception:
            pass
            
    pcap_writer = PcapWriter()
    pcap_writer.open(PCAP_PATH, network=1, snaplen=65535)
    
    tracker = FlowTracker()
    anomaly_detector = AnomalyDetector()
    first_packet_ts = None
    last_packet_ts = None
    packet_count = 0
    total_bytes = 0
    
    live_report = {
        "summary": {
            "total_packets": 0,
            "total_bytes": 0,
            "duration_sec": 0.0,
            "avg_pps": 0.0,
            "avg_kbps": 0.0
        },
        "protocols": {},
        "applications": {},
        "alerts": [],
        "flows": []
    }

# FastAPI routing
@app.get("/")
def get_root():
    return {
        "status": "online",
        "service": "WireSpectra DPI Live Simulator",
        "duration": live_report["summary"]["duration_sec"],
        "packets": live_report["summary"]["total_packets"]
    }

@app.get("/api/report")
def get_api_report():
    with state_lock:
        return live_report

@app.get("/api/pcap")
def get_live_pcap():
    if os.path.exists(PCAP_PATH):
        return FileResponse(
            PCAP_PATH,
            media_type="application/octet-stream",
            filename="live.pcap"
        )
    return Response(status_code=404, content="PCAP not generated yet")

@app.post("/api/reset")
def post_reset():
    with state_lock:
        reset_live_state()
    return {"status": "reset success"}

from pydantic import BaseModel

class BlockRequest(BaseModel):
    domain: str

class PingRequest(BaseModel):
    host: str

@app.get("/api/rules")
def get_rules():
    with state_lock:
        return {"blocked_domains": [r.domain for r in rules_engine.rules if r.action == "BLOCK" and r.domain]}

@app.post("/api/rules/block")
def post_block(req: BlockRequest):
    with state_lock:
        domain = req.domain.strip()
        rules_engine.add_domain_block(domain)
        # Find the rule we just added
        rule_id = f"BLOCK_{domain.upper().replace('.', '_')}"
        added_rule = next((r for r in rules_engine.rules if r.rule_id == rule_id), None)
        
        # Immediately set status of any existing active flows to blocked
        for flow in tracker.flows.values():
            if flow.sni == domain or (hasattr(flow, 'sni') and flow.sni and flow.sni.endswith(domain)):
                flow.state = "BLOCKED"
                flow.matched_rule = added_rule

        # Instantly inject a synthetic SYN + TLS ClientHello sequence to the newly blocked domain
        # so it is guaranteed to show up in the connection table immediately as BLOCKED
        client = random.choice(CLIENT_IPS)
        dst_ip = "142.250.190.46"  # Fallback IP (e.g. google.com)
        for ip, port, proto, s in WEBSITES:
            if s == domain or s.endswith("." + domain) or domain.endswith("." + s):
                dst_ip = ip
                break
        
        src_port = random.randint(49152, 65535)
        ts = time.time()
        
        # SYN packet
        syn_pkt = make_packet(client, dst_ip, src_port, 443, 6, 0x02, b'', 1)
        process_one_packet(syn_pkt, ts)
        
        # TLS ClientHello packet with the blocked domain as SNI
        hello_pkt = make_packet(client, dst_ip, src_port, 443, 6, 0x18, make_tls_hello(domain), 2)
        process_one_packet(hello_pkt, ts + 0.01)
        
        update_live_report()
    return {"status": "ok", "blocked": domain}

@app.post("/api/rules/unblock")
def post_unblock(req: BlockRequest):
    with state_lock:
        rules_engine.remove_domain_block(req.domain)
        # Unblock active and expired flows
        rule_id = f"BLOCK_{req.domain.upper().replace('.', '_')}"
        for flow in list(tracker.flows.values()) + list(tracker.expired_flows.values()):
            matches_sni = (flow.sni == req.domain or (hasattr(flow, 'sni') and flow.sni and flow.sni.endswith(req.domain)))
            matches_rule = (hasattr(flow, 'matched_rule') and flow.matched_rule and flow.matched_rule.rule_id == rule_id)
            
            if flow.state == "BLOCKED" and (matches_sni or matches_rule):
                # Revert status to EXPIRED if in expired archive, otherwise ACTIVE
                if flow in tracker.expired_flows.values():
                    flow.state = "EXPIRED"
                else:
                    flow.state = "ACTIVE"
                flow.matched_rule = None
        update_live_report()
    return {"status": "ok", "unblocked": req.domain}

import subprocess
import socket

def is_host_live(host: str) -> bool:
    # 1. Try system ping (fast, 1 packet, 1 second timeout)
    try:
        res = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5
        )
        if res.returncode == 0:
            return True
    except Exception:
        pass

    # 2. Fallback: Try TCP socket connection to common ports
    try:
        ip = socket.gethostbyname(host)
        for port in [80, 443, 22, 53]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((ip, port))
                s.close()
                return True
            except Exception:
                pass
    except Exception:
        pass
        
    return False

@app.post("/api/ping")
def post_ping(req: PingRequest):
    host = req.host.strip()
    is_live = is_host_live(host)
    status_str = "LIVE" if is_live else "DOWN"
    
    # Try to resolve IP to display in the packet flow
    try:
        target_ip = socket.gethostbyname(host)
    except Exception:
        target_ip = "172.217.16.142" # Fallback mock IP
        
    with state_lock:
        ts = time.time()
        client_ip = random.choice(CLIENT_IPS)
            
        # Simulate 4 ICMP Ping Echo Requests
        for i in range(4):
            # Request
            ping_req = make_packet(client_ip, target_ip, 0, 0, 1, 0, f"Ping Request {i+1}".encode('utf-8'), i+1)
            process_one_packet(ping_req, ts + i * 0.2)
            
            # Reply is only generated if target is LIVE
            if is_live:
                ping_reply = make_packet(target_ip, client_ip, 0, 0, 1, 0, f"Ping Reply {i+1}".encode('utf-8'), i+1)
                process_one_packet(ping_reply, ts + i * 0.2 + 0.05)
            
        update_live_report()
        
    return {
        "status": "ping success", 
        "host": host, 
        "target_ip": target_ip, 
        "is_live": is_live, 
        "host_status": status_str
    }


@app.on_event("startup")
def startup_event():
    # Start packet generator thread
    t = threading.Thread(target=live_generator_loop, daemon=True)
    t.start()

if __name__ == "__main__":
    import uvicorn
    # Allow port to be dynamic via env variable (essential for Back4App)
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
