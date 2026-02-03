import requests
import time
import socket
import platform
import os
from stem import Signal
from stem.control import Controller
from requests.exceptions import RequestException

# VISUAL LIBRARIES
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.align import Align

# Initialize Console
console = Console()

class TorRotator:
    def __init__(self):
        # Auto-discovery for ports (Windows vs Linux)
        self.control_port = self.find_open_port([9151, 9051])
        self.proxy_port = self.find_open_port([9150, 9050])

        if not self.control_port or not self.proxy_port:
            raise ConnectionError("Tor ports not found! Is Tor Browser or Service running?")

        self.proxies = {
            'http': f'socks5h://127.0.0.1:{self.proxy_port}',
            'https': f'socks5h://127.0.0.1:{self.proxy_port}'
        }

    def find_open_port(self, ports):
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    return port
        return None

    def get_current_ip(self):
        """
        Creates a disposable session for each request to force a fresh circuit.
        This solves the 'Keep-Alive' issue where Python sticks to the old IP.
        """
        try:
            with requests.Session() as s:
                s.proxies.update(self.proxies)
                # 'Connection': 'close' forces the socket to reset
                response = s.get('https://httpbin.org/ip', timeout=20, headers={'Connection': 'close'})
                return response.json().get('origin')
        except RequestException:
            return None

    def rotate_ip(self):
        console.print(f"\n[bold yellow][!][/bold yellow] Sending signal via Port {self.control_port}...")
        
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
            
            # Visual Progress Bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), # HATA BURADAYDI, DUZELTILDI
                console=console,
                transient=True 
            ) as progress:
                task = progress.add_task("[cyan]Building new circuit...", total=100)
                for _ in range(100):
                    time.sleep(0.15)
                    progress.update(task, advance=1)
            
            return True
        except Exception as e:
            console.print(f"[bold red][-] Error: {e}[/bold red]")
            return False

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner_text = """
[bold green]AETHER TOR AUTOMATION[/bold green]
[cyan]Dynamic Identity Shifting Tool[/cyan]
[dim]v1.0 Stable Release[/dim]
    """
    console.print(Panel(Align.center(banner_text), title="System Ready", border_style="green", expand=True))

def main():
    print_banner()
    
    try:
        rotator = TorRotator()
    except Exception as e:
        console.print(f"[bold red]❌ Initialization Error:[/bold red] {e}")
        return

    # Info Panel
    info_text = f"Proxy Port: [bold cyan]{rotator.proxy_port}[/bold cyan] | Control Port: [bold cyan]{rotator.control_port}[/bold cyan]"
    console.print(Panel(Align.center(info_text), border_style="blue", expand=True))

    # 1. CHECK INITIAL IDENTITY
    with console.status("[bold blue]Verifying current identity...", spinner="dots"):
        current_ip = rotator.get_current_ip()

    if not current_ip:
        console.print("[bold red]❌ Error: No internet connection via Tor.[/bold red]")
        return

    # Table Setup
    table = Table(title="Identity Shift Analysis", show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Attempt", style="dim", ratio=1)
    table.add_column("IP Address", justify="center", ratio=2)
    table.add_column("Status", justify="right", ratio=1)
    
    table.add_row("Initial", f"[cyan]{current_ip}[/cyan]", platform.system())

    # 2. ROTATION LOOP
    max_attempts = 3
    success = False
    
    for i in range(max_attempts):
        rotator.rotate_ip()
        
        # Verify IP
        with console.status(f"[bold yellow]Verifying IP (Attempt {i+1}/{max_attempts})...", spinner="earth"):
            time.sleep(3) # Wait for Tor bridge latency
            new_ip = rotator.get_current_ip()
        
        if new_ip and new_ip != current_ip:
            table.add_row(f"Attempt {i+1}", f"[green]{new_ip}[/green]", "✅ CHANGED")
            success = True
            break
        else:
            table.add_row(f"Attempt {i+1}", f"[red]{new_ip}[/red]", "❌ SAME")
            console.print(f"[dim]   -> IP persisted. Retrying...[/dim]")

    # 3. RESULT
    console.print(table)
    
    if success:
        console.print("\n[bold green]🚀 SUCCESS: New identity established.[/bold green]")
    else:
        console.print("\n[bold red]💀 FAILED: Could not switch identity.[/bold red]")
        console.print("[yellow]Tip: Try restarting Tor Browser to refresh the bridge connection.[/yellow]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted by user.[/bold red]")