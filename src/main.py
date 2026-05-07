import sys
import io
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pcap_reader import PcapReader
from protocols import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
from flow_tracker import FlowTracker
from rules_engine import RulesEngine
from pcap_writer import PcapWriter
from reporter import CSVReporter, DPIReportGenerator
from rule_builder import InteractiveRuleBuilder
from logger import setup_logger, get_logger
from anomaly_detector import AnomalyDetector

# Force UTF-8 output on Windows to avoid cp1252 UnicodeEncodeError with special chars
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

console = Console()
logger = get_logger("CLI")

def format_hex_preview(data, length=16):
    """Returns a hex representation of the first few bytes."""
    hex_part = " ".join(f"{b:02x}" for b in data[:length])
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:length])
    return f"{hex_part:<48} | {ascii_part}"

def decode_packet_batch(batch):
    """
    Worker function to decode a batch of raw packets.
    batch: list of tuples (packet_count, header, data)
    """
    from protocols import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
    
    results = []
    for packet_count, header, data in batch:
        res = {
            "packet_count": packet_count,
            "header": header,
            "data": data,
            "success": False,
            "is_ip": False,
            "src_str": "N/A",
            "dst_str": "N/A",
            "proto_str": "N/A"
        }
        try:
            eth_frame = EthernetFrame(data)
            res["src_str"] = eth_frame.src_mac
            res["dst_str"] = eth_frame.dst_mac
            res["proto_str"] = eth_frame.get_ethertype_name()
            
            if eth_frame.ethertype == 0x0800:  # IPv4
                try:
                    ip_pkt = IPv4Packet(eth_frame.payload)
                    src_ip = ip_pkt.src_ip
                    dst_ip = ip_pkt.dst_ip
                    protocol = ip_pkt.protocol
                    
                    src_port = 0
                    dst_port = 0
                    res["src_str"] = src_ip
                    res["dst_str"] = dst_ip
                    res["proto_str"] = ip_pkt.get_protocol_name()
                    
                    tcp_payload = b''
                    fin_flag = False
                    rst_flag = False
                    pkt_payload = b''
                    tcp_flags = []
                    
                    if ip_pkt.protocol == 6:  # TCP
                        try:
                            tcp_pkt = TCPPacket(ip_pkt.payload)
                            src_port = tcp_pkt.src_port
                            dst_port = tcp_pkt.dst_port
                            res["src_str"] = f"{src_ip}:{src_port}"
                            res["dst_str"] = f"{dst_ip}:{dst_port}"
                            flags = tcp_pkt.get_flags_str()
                            res["proto_str"] = f"TCP [{flags}]" if flags else "TCP"
                            tcp_payload = tcp_pkt.payload
                            pkt_payload = tcp_payload
                            fin_flag = tcp_pkt.fin
                            rst_flag = tcp_pkt.rst
                            
                            if tcp_pkt.syn: tcp_flags.append("SYN")
                            if tcp_pkt.ack: tcp_flags.append("ACK")
                            if tcp_pkt.fin: tcp_flags.append("FIN")
                            if tcp_pkt.rst: tcp_flags.append("RST")
                            if tcp_pkt.psh: tcp_flags.append("PSH")
                            if tcp_pkt.urg: tcp_flags.append("URG")
                        except Exception:
                            pass
                    elif ip_pkt.protocol == 17:  # UDP
                        try:
                            udp_pkt = UDPPacket(ip_pkt.payload)
                            src_port = udp_pkt.src_port
                            dst_port = udp_pkt.dst_port
                            res["src_str"] = f"{src_ip}:{src_port}"
                            res["dst_str"] = f"{dst_ip}:{dst_port}"
                            res["proto_str"] = "UDP"
                            pkt_payload = udp_pkt.payload
                        except Exception:
                            pass
                            
                    res["is_ip"] = True
                    res["ip_data"] = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "tcp_payload": tcp_payload,
                        "fin_flag": fin_flag,
                        "rst_flag": rst_flag,
                        "pkt_payload": pkt_payload,
                        "tcp_flags": tcp_flags
                    }
                except Exception:
                    pass
            res["success"] = True
        except Exception:
            pass
        results.append(res)
    return results

@click.command()
@click.argument('filepath', required=False)
@click.option('--rules', type=click.Path(exists=True), help='Path to rules JSON file')
@click.option('--export-blocked', type=click.Path(), help='Path to export blocked packets as PCAP')
@click.option('--export-csv', type=click.Path(), help='Path to export flow statistics as CSV')
@click.option('--report', is_flag=True, help='Print advanced traffic and protocol distribution reports')
@click.option('--new-rule', is_flag=True, help='Launch interactive rule builder')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR'], case_sensitive=False), default='WARNING', help='Set logging verbosity level')
@click.option('--log-file', type=click.Path(), default='dpi_engine.log', help='Path to output log file')
@click.option('--parallel', is_flag=True, help='Enable parallel packet decoding mode')
@click.option('--workers', type=int, default=None, help='Number of parallel worker processes')
@click.option('--export-json', type=click.Path(), help='Path to export flow statistics as JSON')
def main(filepath, rules, export_blocked, export_csv, report, new_rule, log_level, log_file, parallel, workers, export_json):
    setup_logger(log_level, log_file)
    logger.info("WireSpectra DPI Engine starting up...")

    welcome_message = Panel.fit(
        "[bold blue]WireSpectra DPI Engine[/bold blue]\n"
        "[white]System Initialized[/white]",
        border_style="bright_magenta"
    )
    console.print(welcome_message)

    if new_rule:
        try:
            rules_file = click.prompt("Path to rules JSON file to save to", default="rules.json")
            rule = InteractiveRuleBuilder.prompt_rule()
            InteractiveRuleBuilder.save_rule_to_file(rule, rules_file)
        except Exception as e:
            console.print(f"[bold red]Error in rule builder:[/bold red] {str(e)}")
        return

    if not filepath:
        console.print("[yellow]Usage: python src/main.py <path_to_pcap>[/yellow]")
        return

    rules_engine = RulesEngine()
    anomaly_detector = AnomalyDetector()
    if rules:
        try:
            rules_engine.load_rules_from_file(rules)
            console.print(f"[*] Loaded {len(rules_engine.rules)} rules from [cyan]{rules}[/cyan]")
        except Exception as e:
            logger.error(f"Failed to load rules file: {str(e)}")
            console.print(f"[bold red]Error loading rules file:[/bold red] {str(e)}")
            return

    reader = PcapReader()
    tracker = FlowTracker()
    try:
        logger.info(f"Opening PCAP file: {filepath}")
        console.print(f"[*] Opening file: [cyan]{filepath}[/cyan]...")
        reader.open(filepath)
        
        # Global Header Table
        header_table = Table(title="PCAP Global Header", box=None)
        header_table.add_column("Field", style="cyan")
        header_table.add_column("Value", style="green")
        header_table.add_row("Magic Number", hex(reader.magic_number))
        header_table.add_row("Version", f"{reader.version_major}.{reader.version_minor}")
        header_table.add_row("Network Type", "Ethernet (1)" if reader.network == 1 else str(reader.network))
        console.print(header_table)

        # Packet Feed
        console.print("\n[*] Processing packets...")
        
        packet_table = Table(title="Packet Preview (First 5)", box=None)
        packet_table.add_column("#", style="dim")
        packet_table.add_column("Timestamp", style="yellow")
        packet_table.add_column("Source", style="cyan")
        packet_table.add_column("Destination", style="cyan")
        packet_table.add_column("Proto/Type", style="green")
        packet_table.add_column("Size", style="green")
        packet_table.add_column("Hex Preview (First 16 bytes)", style="magenta")

        packet_count = 0
        total_bytes = 0
        first_packet_ts = None
        last_packet_ts = None
        
        if parallel:
            import multiprocessing
            # Load raw packets
            all_raw_packets = list(reader)
            # Batch them
            batch_size = 100
            batches = []
            current_batch = []
            for i, (header, data) in enumerate(all_raw_packets):
                current_batch.append((i + 1, header, data))
                if len(current_batch) == batch_size:
                    batches.append(current_batch)
                    current_batch = []
            if current_batch:
                batches.append(current_batch)
                
            num_workers = workers if workers else multiprocessing.cpu_count()
            with multiprocessing.Pool(processes=num_workers) as pool:
                results_generator = pool.imap(decode_packet_batch, batches)
                for batch_results in results_generator:
                    for res in batch_results:
                        packet_count = res["packet_count"]
                        header = res["header"]
                        data = res["data"]
                        
                        total_bytes += header['length']
                        if first_packet_ts is None:
                            first_packet_ts = header['timestamp']
                        last_packet_ts = header['timestamp']
                        
                        src_str = res["src_str"]
                        dst_str = res["dst_str"]
                        proto_str = res["proto_str"]
                        
                        if res["success"] and res["is_ip"]:
                            ip_data = res["ip_data"]
                            src_ip = ip_data["src_ip"]
                            dst_ip = ip_data["dst_ip"]
                            src_port = ip_data["src_port"]
                            dst_port = ip_data["dst_port"]
                            protocol = ip_data["protocol"]
                            tcp_payload = ip_data["tcp_payload"]
                            fin_flag = ip_data["fin_flag"]
                            rst_flag = ip_data["rst_flag"]
                            pkt_payload = ip_data["pkt_payload"]
                            tcp_flags = ip_data["tcp_flags"]
                            
                            # Run Anomaly Detection
                            alert = anomaly_detector.process_packet(
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                protocol=protocol,
                                tcp_flags=tcp_flags
                            )
                            if alert:
                                console.print(Panel(
                                    f"[bold yellow]⚠️ WARNING: Security Anomaly Alert [{alert['type']}][/bold yellow]\n"
                                    f"[white]Target: {alert['target']}[/white]\n"
                                    f"[white]{alert['details']}[/white]",
                                    border_style="yellow"
                                ))

                            # Process connection flow tracking
                            flow = tracker.process_packet(
                                src_ip=src_ip,
                                src_port=src_port,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                protocol=protocol,
                                length=header['length'],
                                timestamp=header['timestamp'],
                                payload=tcp_payload,
                                fin=fin_flag,
                                rst=rst_flag,
                                raw_data=data
                            )

                            # Rules Engine Evaluation
                            if rules:
                                matched_rule = rules_engine.evaluate_flow(flow, payload=pkt_payload)
                                if matched_rule:
                                    if matched_rule.action == "BLOCK":
                                        flow.state = "BLOCKED"
                                    flow.matched_rule = matched_rule
                                    
                                    if matched_rule.action == "BLOCK":
                                        proto_str = f"[red]BLOCK ({matched_rule.rule_id})[/red] " + proto_str
                                    else:
                                        proto_str = f"[yellow]ALERT ({matched_rule.rule_id})[/yellow] " + proto_str
                                        
                            if packet_count % 100 == 0:
                                tracker.cleanup_expired_flows(header['timestamp'])
                                if rules:
                                    if rules_engine.check_and_reload():
                                        console.print(f"\n[bold green][*] Rules configuration modified. Hot-reloaded {len(rules_engine.rules)} rules.[/bold green]\n")
                        
                        if packet_count <= 5:
                            packet_table.add_row(
                                str(packet_count),
                                f"{header['timestamp']:.6f}",
                                src_str,
                                dst_str,
                                proto_str,
                                f"{header['length']} B",
                                format_hex_preview(data)
                            )
                        if packet_count == 5:
                            console.print(packet_table)
                            console.print("    [dim]... processing remaining packets ...[/dim]")
        else:
            for header, data in reader:
                packet_count += 1
                total_bytes += header['length']
                if first_packet_ts is None:
                    first_packet_ts = header['timestamp']
                last_packet_ts = header['timestamp']
                
                src_str, dst_str, proto_str = "N/A", "N/A", "N/A"
                try:
                    eth_frame = EthernetFrame(data)
                    src_str = eth_frame.src_mac
                    dst_str = eth_frame.dst_mac
                    proto_str = eth_frame.get_ethertype_name()
                    
                    if eth_frame.ethertype == 0x0800:  # IPv4
                        try:
                            ip_pkt = IPv4Packet(eth_frame.payload)
                            src_ip = ip_pkt.src_ip
                            dst_ip = ip_pkt.dst_ip
                            protocol = ip_pkt.protocol
                            
                            src_port = 0
                            dst_port = 0
                            src_str = src_ip
                            dst_str = dst_ip
                            proto_str = ip_pkt.get_protocol_name()
                            
                            tcp_payload = b''
                            fin_flag = False
                            rst_flag = False
                            pkt_payload = b''
                            tcp_flags = []
                            if ip_pkt.protocol == 6:  # TCP
                                try:
                                    tcp_pkt = TCPPacket(ip_pkt.payload)
                                    src_port = tcp_pkt.src_port
                                    dst_port = tcp_pkt.dst_port
                                    src_str = f"{src_ip}:{src_port}"
                                    dst_str = f"{dst_ip}:{dst_port}"
                                    flags = tcp_pkt.get_flags_str()
                                    proto_str = f"TCP [{flags}]" if flags else "TCP"
                                    tcp_payload = tcp_pkt.payload
                                    pkt_payload = tcp_payload
                                    fin_flag = tcp_pkt.fin
                                    rst_flag = tcp_pkt.rst
                                    
                                    if tcp_pkt.syn: tcp_flags.append("SYN")
                                    if tcp_pkt.ack: tcp_flags.append("ACK")
                                    if tcp_pkt.fin: tcp_flags.append("FIN")
                                    if tcp_pkt.rst: tcp_flags.append("RST")
                                    if tcp_pkt.psh: tcp_flags.append("PSH")
                                    if tcp_pkt.urg: tcp_flags.append("URG")
                                except Exception:
                                    pass
                            elif ip_pkt.protocol == 17:  # UDP
                                try:
                                    udp_pkt = UDPPacket(ip_pkt.payload)
                                    src_port = udp_pkt.src_port
                                    dst_port = udp_pkt.dst_port
                                    src_str = f"{src_ip}:{src_port}"
                                    dst_str = f"{dst_ip}:{dst_port}"
                                    proto_str = "UDP"
                                    pkt_payload = udp_pkt.payload
                                except Exception:
                                    pass
                            
                            # Run Anomaly Detection
                            alert = anomaly_detector.process_packet(
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                protocol=protocol,
                                tcp_flags=tcp_flags
                            )
                            if alert:
                                console.print(Panel(
                                    f"[bold yellow]⚠️ WARNING: Security Anomaly Alert [{alert['type']}][/bold yellow]\n"
                                    f"[white]Target: {alert['target']}[/white]\n"
                                    f"[white]{alert['details']}[/white]",
                                    border_style="yellow"
                                ))
    
                            # Process connection flow tracking
                            flow = tracker.process_packet(
                                src_ip=src_ip,
                                src_port=src_port,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                protocol=protocol,
                                length=header['length'],
                                timestamp=header['timestamp'],
                                payload=tcp_payload,
                                fin=fin_flag,
                                rst=rst_flag,
                                raw_data=data
                            )
    
                            # Rules Engine Evaluation
                            if rules:
                                matched_rule = rules_engine.evaluate_flow(flow, payload=pkt_payload)
                                if matched_rule:
                                    if matched_rule.action == "BLOCK":
                                        flow.state = "BLOCKED"
                                    # Store matched rule on flow for metadata / printing
                                    flow.matched_rule = matched_rule
                                    
                                    # Add alert prefix to the CLI packet type
                                    if matched_rule.action == "BLOCK":
                                        proto_str = f"[red]BLOCK ({matched_rule.rule_id})[/red] " + proto_str
                                    else:
                                        proto_str = f"[yellow]ALERT ({matched_rule.rule_id})[/yellow] " + proto_str
                            # Periodically clean up expired flows and reload rules (every 100 packets)
                            if packet_count % 100 == 0:
                                tracker.cleanup_expired_flows(header['timestamp'])
                                if rules:
                                    if rules_engine.check_and_reload():
                                        console.print(f"\n[bold green][*] Rules configuration modified. Hot-reloaded {len(rules_engine.rules)} rules.[/bold green]\n")
                        except Exception:
                            pass
                except Exception:
                    pass
    
                if packet_count <= 5:
                    packet_table.add_row(
                        str(packet_count),
                        f"{header['timestamp']:.6f}",
                        src_str,
                        dst_str,
                        proto_str,
                        f"{header['length']} B",
                        format_hex_preview(data)
                    )
                
                if packet_count == 5:
                    console.print(packet_table)
                    console.print("    [dim]... processing remaining packets ...[/dim]")
    
            if packet_count < 5:
                console.print(packet_table)

        console.print(f"\n[green][OK][/green] Analysis Complete.")
        console.print(f"    [bold]Total Packets:[/bold] {packet_count}")
        console.print(f"    [bold]Total Traffic:[/bold] {total_bytes / 1024:.2f} KB")

        # Display Anomaly Alerts Summary Table
        if anomaly_detector.all_alerts:
            alerts_table = Table(title="Security Anomaly Alerts", box=None)
            alerts_table.add_column("Type", style="bold red")
            alerts_table.add_column("Target/Source", style="cyan")
            alerts_table.add_column("Details", style="yellow")
            for alert in anomaly_detector.all_alerts:
                alerts_table.add_row(alert["type"], alert["target"], alert["details"])
            console.print("\n")
            console.print(alerts_table)
        
        # Display Flow tracking table
        all_flows = list(tracker.flows.values()) + list(tracker.expired_flows.values())
        if all_flows:
            flow_table = Table(title=f"Flows Summary (Total: {len(all_flows)}, Expired: {len(tracker.expired_flows)})", box=None)
            flow_table.add_column("Protocol", style="green")
            flow_table.add_column("Application/SNI", style="magenta")
            flow_table.add_column("Endpoint A", style="cyan")
            flow_table.add_column("Endpoint B", style="cyan")
            flow_table.add_column("Packets", style="magenta")
            flow_table.add_column("Bytes", style="yellow")
            flow_table.add_column("Duration", style="yellow")
            flow_table.add_column("Status", style="red")
            
            # Sort flows by byte count descending, showing top 10
            sorted_flows = sorted(all_flows, key=lambda f: f.byte_count, reverse=True)[:10]
            for flow in sorted_flows:
                ip_a, port_a, ip_b, port_b, _ = flow.flow_key
                endpoint_a = f"{ip_a}:{port_a}" if port_a else ip_a
                endpoint_b = f"{ip_b}:{port_b}" if port_b else ip_b
                
                app_str = f"{flow.app_name} ({flow.sni})" if flow.sni else "N/A"
                
                # Format status with rules action if applicable
                if flow.state == "BLOCKED":
                    status_str = f"[red]Blocked ({flow.matched_rule.rule_id})[/red]"
                elif hasattr(flow, 'matched_rule') and flow.matched_rule and flow.matched_rule.action == "ALERT":
                    status_str = f"[yellow]Alerted ({flow.matched_rule.rule_id})[/yellow]"
                else:
                    status_str = "Active" if flow.state == "ACTIVE" else "Closed/Expired"
                
                flow_table.add_row(
                    flow.protocol_name,
                    app_str,
                    endpoint_a,
                    endpoint_b,
                    str(flow.packet_count),
                    f"{flow.byte_count} B",
                    f"{flow.duration:.3f} s",
                    status_str
                )
            console.print("\n")
            console.print(flow_table)
        
        # Export blocked flows if requested
        if export_blocked:
            blocked_packets = []
            for flow in all_flows:
                if flow.state == "BLOCKED":
                    blocked_packets.extend(flow.packets_buffer)
            
            if blocked_packets:
                # Sort packets chronologically by timestamp
                blocked_packets.sort(key=lambda x: x[0])
                
                writer = PcapWriter()
                try:
                    writer.open(export_blocked, network=reader.network, snaplen=reader.snaplen)
                    total_bytes_written = 0
                    for ts, pkt_data, orig_len in blocked_packets:
                        writer.write_packet(ts, pkt_data, orig_len)
                        total_bytes_written += len(pkt_data)
                    writer.close()
                    logger.info(f"Successfully exported {len(blocked_packets)} blocked packets ({total_bytes_written} bytes) to {export_blocked}")
                    console.print(f"\n[green][OK][/green] Exported {len(blocked_packets)} blocked packets ({total_bytes_written / 1024:.2f} KB) to [cyan]{export_blocked}[/cyan]")
                except Exception as e:
                    logger.error(f"Error exporting packets: {str(e)}")
                    console.print(f"[bold red]Error exporting packets:[/bold red] {str(e)}")
            else:
                logger.info("No blocked packets found to export.")
                console.print("\n[*] No blocked packets to export.")

        # Export CSV if requested
        if export_csv and all_flows:
            try:
                CSVReporter.export_flows(all_flows, export_csv)
                logger.info(f"Successfully exported flow statistics to {export_csv}")
                console.print(f"\n[green][OK][/green] Flow statistics exported to CSV: [cyan]{export_csv}[/cyan]")
            except Exception as e:
                logger.error(f"Error exporting CSV: {str(e)}")
                console.print(f"[bold red]Error exporting CSV:[/bold red] {str(e)}")

        # Export JSON if requested
        if export_json and all_flows:
            import json
            try:
                duration = (last_packet_ts - first_packet_ts) if (last_packet_ts and first_packet_ts) else 0.0
                throughput = DPIReportGenerator.generate_throughput_summary(packet_count, total_bytes, duration)
                dist = DPIReportGenerator.generate_distribution_report(all_flows)
                
                # Format flows
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
                
                report_data = {
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
                
                with open(export_json, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, indent=4)
                    
                logger.info(f"Successfully exported flow statistics in JSON format to {export_json}")
                console.print(f"\n[green][OK][/green] Flow statistics exported to JSON: [cyan]{export_json}[/cyan]")
            except Exception as e:
                logger.error(f"Error exporting JSON: {str(e)}")
                console.print(f"[bold red]Error exporting JSON:[/bold red] {str(e)}")

        # Print advanced report if requested
        if report and all_flows:
            duration = (last_packet_ts - first_packet_ts) if (last_packet_ts and first_packet_ts) else 0.0
            throughput = DPIReportGenerator.generate_throughput_summary(packet_count, total_bytes, duration)
            dist = DPIReportGenerator.generate_distribution_report(all_flows)
            
            report_title = Panel(
                f"[bold cyan]WireSpectra DPI Advanced Analysis Report[/bold cyan]\n"
                f"[white]Duration: {duration:.3f} seconds[/white]\n"
                f"[white]Total Packets: {packet_count} | Total Bytes: {total_bytes} ({total_bytes / 1024:.2f} KB)[/white]\n"
                f"[white]Avg Throughput: {throughput['avg_pps']:.2f} pps | {throughput['avg_kbps']:.2f} kbps[/white]",
                border_style="cyan"
            )
            console.print("\n")
            console.print(report_title)
            
            # Protocol Distribution Table
            proto_table = Table(title="Protocol Distribution", box=None)
            proto_table.add_column("Protocol", style="green")
            proto_table.add_column("Packets", style="magenta")
            proto_table.add_column("Packets %", style="cyan")
            proto_table.add_column("Bytes", style="yellow")
            proto_table.add_column("Bytes %", style="cyan")
            for proto, stats in dist["protocols"].items():
                proto_table.add_row(
                    proto,
                    str(stats["packets"]),
                    f"{stats['packets_pct']:.1f}%",
                    f"{stats['bytes']} B",
                    f"{stats['bytes_pct']:.1f}%"
                )
            console.print(proto_table)
            
            # Application Distribution Table
            app_table = Table(title="Application/Service Distribution", box=None)
            app_table.add_column("Application", style="green")
            app_table.add_column("Packets", style="magenta")
            app_table.add_column("Packets %", style="cyan")
            app_table.add_column("Bytes", style="yellow")
            app_table.add_column("Bytes %", style="cyan")
            for app, stats in dist["applications"].items():
                app_table.add_row(
                    app,
                    str(stats["packets"]),
                    f"{stats['packets_pct']:.1f}%",
                    f"{stats['bytes']} B",
                    f"{stats['bytes_pct']:.1f}%"
                )
            console.print("\n")
            console.print(app_table)

        logger.info("WireSpectra DPI Engine analysis complete")
        reader.close()
        
    except Exception as e:
        logger.error(f"Fatal execution error: {str(e)}")
        console.print(f"[bold red]Error:[/bold red] {str(e)}")

if __name__ == "__main__":
    main()
