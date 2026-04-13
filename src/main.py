import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pcap_reader import PcapReader

console = Console()

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
        
        # Display Header Information in a nice table
        table = Table(title="PCAP Global Header")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Magic Number", hex(reader.magic_number))
        table.add_row("Version", f"{reader.version_major}.{reader.version_minor}")
        table.add_row("Snap Length", str(reader.snaplen))
        table.add_row("Network Type", "Ethernet (1)" if reader.network == 1 else str(reader.network))
        
        console.print(table)
        reader.close()
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")

if __name__ == "__main__":
    main()
