import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pcap_reader import PcapReader
from protocols import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
from flow_tracker import FlowTracker
from rules_engine import RulesEngine

console = Console()

def format_hex_preview(data, length=16):
    """Returns a hex representation of the first few bytes."""
    hex_part = " ".join(f"{b:02x}" for b in data[:length])
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:length])
    return f"{hex_part:<48} | {ascii_part}"

@click.command()
@click.argument('filepath', required=False)
@click.option('--rules', type=click.Path(exists=True), help='Path to rules JSON file')
def main(filepath, rules):
    welcome_message = Panel.fit(
        "[bold blue]WireSpectra DPI Engine[/bold blue]\n"
        "[white]System Initialized[/white]",
        border_style="bright_magenta"
    )
    console.print(welcome_message)

    if not filepath:
        console.print("[yellow]Usage: python src/main.py <path_to_pcap>[/yellow]")
        return

    rules_engine = RulesEngine()
    if rules:
        try:
            rules_engine.load_rules_from_file(rules)
            console.print(f"[*] Loaded {len(rules_engine.rules)} rules from [cyan]{rules}[/cyan]")
        except Exception as e:
            console.print(f"[bold red]Error loading rules file:[/bold red] {str(e)}")
            return

    reader = PcapReader()
    tracker = FlowTracker()
    try:
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
        
        for header, data in reader:
            packet_count += 1
            total_bytes += header['length']
            
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
                                fin_flag = tcp_pkt.fin
                                rst_flag = tcp_pkt.rst
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
                            except Exception:
                                pass
                        
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
                            rst=rst_flag
                        )

                        # Rules Engine Evaluation
                        if rules:
                            matched_rule = rules_engine.evaluate_flow(flow)
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
                        
                        # Periodically clean up expired flows (every 100 packets)
                        if packet_count % 100 == 0:
                            tracker.cleanup_expired_flows(header['timestamp'])
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

        console.print(f"\n[green]✔[/green] Analysis Complete.")
        console.print(f"    [bold]Total Packets:[/bold] {packet_count}")
        console.print(f"    [bold]Total Traffic:[/bold] {total_bytes / 1024:.2f} KB")
        
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
        
        reader.close()
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")

if __name__ == "__main__":
    main()
