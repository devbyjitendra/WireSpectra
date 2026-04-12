import sys
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    welcome_message = Panel.fit(
        "[bold blue]WireSpectra DPI Engine[/bold blue]\n"
        "[white]System Initialized[/white]",
        border_style="bright_magenta"
    )
    console.print(welcome_message)
    
    console.print(f"[green]✔[/green] Python {sys.version.split()[0]} detected.")
    console.print("[yellow]![/yellow] Initializing project modules...")
    console.print("[green]✔[/green] Project structure ready.")

if __name__ == "__main__":
    main()
