import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pcap_reader import PcapReader
from protocols import EthernetFrame, IPv4Packet

console = Console()

def format_hex_preview(data, length=16):
    """Returns a hex representation of the first few bytes."""
    hex_part = " ".join(f"{b:02x}" for b in data[:length])
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:length])
    return f"{hex_part:<48} | {ascii_part}"

@click.command()
@click.argument('filepath', required=False)
def main(filepath):
    welcome_message = Panel.fit(
        "[bold blue]WireSpectra DPI Engine[/bold blue]\n"
        "[white]System Initialized[/white]",
        border_style="bright_magenta"
    )
    console.print(welcome_message)

    if not filepath:
        console.print("[yellow]Usage: python src/main.py <path_to_pcap>[/yellow]")
        return

    reader = PcapReader()
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
            
            if packet_count <= 5:
                src_str, dst_str, proto_str = "N/A", "N/A", "N/A"
                try:
                    eth_frame = EthernetFrame(data)
                    src_str = eth_frame.src_mac
                    dst_str = eth_frame.dst_mac
                    proto_str = eth_frame.get_ethertype_name()
                    
                    if eth_frame.ethertype == 0x0800:  # IPv4
                        try:
                            ip_pkt = IPv4Packet(eth_frame.payload)
                            src_str = ip_pkt.src_ip
                            dst_str = ip_pkt.dst_ip
                            proto_str = ip_pkt.get_protocol_name()
                        except Exception:
                            pass
                except Exception:
                    pass

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
        
        reader.close()
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")

if __name__ == "__main__":
    main()
