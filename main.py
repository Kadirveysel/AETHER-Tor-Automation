"""AETHER command-line interface: rotate your Tor identity and verify it."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from typing import List, Optional

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rotator import (
    TorAuthError,
    TorConnectionError,
    TorError,
    TorRotator,
    __version__,
)

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aether",
        description="Rotate your Tor exit IP via the control port and verify the result.",
    )
    parser.add_argument(
        "-n", "--count", type=int, default=1,
        help="number of identity rotations to perform (default: 1)",
    )
    parser.add_argument(
        "-i", "--interval", type=float, default=0.0,
        help="extra seconds to wait between rotations (Tor already enforces ~10s)",
    )
    parser.add_argument(
        "-a", "--attempts", type=int, default=3,
        help="NEWNYM retries per rotation if Tor picks the same exit (default: 3)",
    )
    parser.add_argument("--control-port", type=int, help="Tor control port (default: auto-detect)")
    parser.add_argument("--socks-port", type=int, help="Tor SOCKS port (default: auto-detect)")
    parser.add_argument(
        "--ask-password", action="store_true",
        help="prompt for the control-port password (or set TOR_CONTROL_PASSWORD)",
    )
    parser.add_argument(
        "--no-clear", action="store_true", help="do not clear the screen on start",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def tor_label(is_tor: Optional[bool]) -> str:
    """Table cell for the 'Via Tor' column; None means the endpoint can't tell."""
    if is_tor is None:
        return "[dim]?[/dim]"
    return "yes" if is_tor else "[red]no[/red]"


def print_banner() -> None:
    banner = (
        "[bold green]AETHER TOR AUTOMATION[/bold green]\n"
        "[cyan]Tor identity rotation & exit-IP verification[/cyan]\n"
        f"[dim]v{__version__}[/dim]"
    )
    console.print(Panel(Align.center(banner), border_style="green", expand=True))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.count < 1 or args.attempts < 1 or args.interval < 0:
        console.print("[bold red]--count and --attempts must be >= 1, --interval >= 0[/bold red]")
        return 2

    if not args.no_clear:
        console.clear()
    print_banner()

    password = os.environ.get("TOR_CONTROL_PASSWORD")
    if args.ask_password:
        password = getpass.getpass("Tor control password: ")

    try:
        rotator = TorRotator(
            control_port=args.control_port,
            socks_port=args.socks_port,
            password=password,
        )
    except TorError as exc:
        console.print(f"[bold red]Initialization error:[/bold red] {exc}")
        return 1

    console.print(
        Panel(
            Align.center(
                f"SOCKS port: [bold cyan]{rotator.socks_port}[/bold cyan]  |  "
                f"Control port: [bold cyan]{rotator.control_port}[/bold cyan]"
            ),
            border_style="blue",
            expand=True,
        )
    )

    try:
        with console.status("[bold blue]Checking current exit...", spinner="dots"):
            current = rotator.get_exit_info()
    except TorError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    if current.is_tor is False:
        console.print(
            "[bold yellow]Warning:[/bold yellow] the Tor Project reports this traffic "
            "is NOT exiting through Tor. Check which proxy port is in use."
        )
    elif current.is_tor is None:
        console.print(
            "[dim]Note: check.torproject.org was unreachable, so a fallback IP service "
            "answered. The IP is shown, but Tor usage cannot be confirmed.[/dim]"
        )

    table = Table(title="Identity rotation", header_style="bold magenta", expand=True)
    table.add_column("#", style="dim", ratio=1)
    table.add_column("Exit IP", justify="center", ratio=3)
    table.add_column("Via Tor", justify="center", ratio=1)
    table.add_column("Status", justify="right", ratio=2)
    table.add_row("start", f"[cyan]{current.ip}[/cyan]", tor_label(current.is_tor), "-")

    changed_count = 0
    exit_code = 0
    try:
        for index in range(1, args.count + 1):
            try:
                with console.status(
                    f"[bold yellow]Rotation {index}/{args.count} "
                    "(waiting for Tor, then verifying)...",
                    spinner="earth",
                ):
                    result = rotator.rotate_ip(max_attempts=args.attempts, previous=current)
            except TorAuthError as exc:
                console.print(f"[bold red]Authentication error:[/bold red] {exc}")
                exit_code = 1
                break
            except TorConnectionError as exc:
                console.print(f"[bold red]Connection error:[/bold red] {exc}")
                exit_code = 1
                break
            except TorError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                exit_code = 1
                break

            current = result.current
            via_tor = tor_label(current.is_tor)
            if result.changed:
                changed_count += 1
                status = f"[green]changed[/green] (try {result.attempts})"
                ip_cell = f"[green]{current.ip}[/green]"
            else:
                status = "[yellow]same exit chosen[/yellow]"
                ip_cell = f"[yellow]{current.ip}[/yellow]"
            table.add_row(str(index), ip_cell, via_tor, status)

            if index < args.count and args.interval > 0:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted by user.[/bold red]")
        exit_code = 130

    console.print(table)
    console.print(f"\n{changed_count} of {args.count} rotation(s) produced a new exit IP.")
    if exit_code == 0 and changed_count < args.count:
        console.print(
            "[dim]Tor can legitimately pick the same exit again; "
            "increase --attempts if you need a guaranteed change.[/dim]"
        )
        exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
