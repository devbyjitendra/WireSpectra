import csv
from collections import defaultdict

class CSVReporter:
    @staticmethod
    def export_flows(flows, filepath):
        """
        Exports a list of Flow objects to a CSV file.
        """
        headers = [
            "flow_id", "protocol", "app_name", "sni",
            "src_ip", "src_port", "dst_ip", "dst_port",
            "packets", "bytes", "duration_sec",
            "packets_per_sec", "bytes_per_sec", "status"
        ]
        
        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for idx, flow in enumerate(flows, 1):
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
                elif hasattr(flow, 'last_active') and flow in flows: # if in expired list
                    # if it is in the expired flows dict, it's inactive/expired
                    status_str = "EXPIRED"

                writer.writerow({
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
        return True


class DPIReportGenerator:
    @staticmethod
    def generate_distribution_report(flows):
        """
        Generates byte and packet distribution reports grouped by protocol and application.
        """
        proto_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        app_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        
        total_packets = 0
        total_bytes = 0
        
        for flow in flows:
            pkts = flow.packet_count
            bytes_count = flow.byte_count
            
            total_packets += pkts
            total_bytes += bytes_count
            
            # Group by protocol
            proto_stats[flow.protocol_name]["packets"] += pkts
            proto_stats[flow.protocol_name]["bytes"] += bytes_count
            
            # Group by app
            app_name = flow.app_name or "Unclassified"
            app_stats[app_name]["packets"] += pkts
            app_stats[app_name]["bytes"] += bytes_count

        # Compute percentages
        proto_report = {}
        for proto, stats in proto_stats.items():
            proto_report[proto] = {
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "packets_pct": (stats["packets"] / total_packets * 100) if total_packets > 0 else 0,
                "bytes_pct": (stats["bytes"] / total_bytes * 100) if total_bytes > 0 else 0
            }
            
        app_report = {}
        for app, stats in app_stats.items():
            app_report[app] = {
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "packets_pct": (stats["packets"] / total_packets * 100) if total_packets > 0 else 0,
                "bytes_pct": (stats["bytes"] / total_bytes * 100) if total_bytes > 0 else 0
            }
            
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocols": proto_report,
            "applications": app_report
        }

    @staticmethod
    def generate_throughput_summary(total_packets, total_bytes, duration):
        """
        Generates global throughput summaries based on duration.
        """
        if duration <= 0:
            return {
                "duration": 0,
                "avg_pps": 0.0,
                "avg_bps": 0.0,
                "avg_kbps": 0.0
            }
            
        avg_pps = total_packets / duration
        avg_bps = (total_bytes * 8) / duration # bits per second
        
        return {
            "duration": duration,
            "avg_pps": avg_pps,
            "avg_bps": avg_bps,
            "avg_kbps": avg_bps / 1000
        }
