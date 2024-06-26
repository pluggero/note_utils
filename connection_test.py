#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
from datetime import datetime

import nmap
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


def check_sudo():
    if os.geteuid() != 0:
        console.print(
            "[bold red]This script must be run with sudo privileges.[/bold red]"
        )
        sys.exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Perform an Nmap ping sweep and basic port scan on given hosts."
    )
    parser.add_argument(
        "-f",
        "--file",
        type=argparse.FileType("r"),
        help="File containing list of hosts",
    )
    parser.add_argument("hosts", nargs="*", help="List of hosts")
    parser.add_argument(
        "--verbose", action="store_true", help="Display detailed information"
    )
    parser.add_argument(
        "--md-table",
        action="store_true",
        help="Output results in Markdown table format",
    )
    return parser.parse_args()


def read_hosts_from_stdin(verbose):
    if verbose:
        console.print(
            "Reading hosts from stdin. Press Ctrl+D (or Ctrl+Z on Windows) to end input."
        )
    return [line.strip() for line in sys.stdin if line.strip()]


def perform_ping_sweep(nm, hosts, verbose=False):
    up_hosts = []
    down_hosts = []

    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[blue]Performing ping sweep...", total=len(hosts))

        for host in hosts:
            if verbose:
                console.print(f"Pinging {host}...")
            try:
                nm.scan(host, arguments="-sn")
                if nm.all_hosts():
                    if verbose:
                        console.print(f"[green]{host} is up.[/green]")
                    up_hosts.append(host)
                else:
                    if verbose:
                        console.print(f"[red]{host} is down.[/red]")
                    down_hosts.append(host)
            except Exception as e:
                if verbose:
                    console.print(f"[red]Error scanning {host}: {e}[/red]")
                down_hosts.append(host)
            progress.advance(task)

    return up_hosts, down_hosts


def perform_sudo_port_scan(hosts, verbose=False):
    up_hosts = []
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[blue]Performing port scan...", total=len(hosts))

        for host in hosts:
            try:
                if verbose:
                    console.print(
                        f"Scanning top 1000 ports on {host} with sudo nmap -Pn..."
                    )
                result = subprocess.run(
                    ["sudo", "nmap", "-Pn", "--top-ports", "1000", host],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                open_ports = [
                    line.split("/")[0]
                    for line in result.stdout.splitlines()
                    if "/tcp" in line and "open" in line
                ]
                if open_ports:
                    up_hosts.append(host)
            except subprocess.CalledProcessError as e:
                if verbose:
                    console.print(f"[red]Error scanning ports on {host}: {e}[/red]")
            progress.advance(task)

    return up_hosts


def main():
    check_sudo()
    args = parse_arguments()

    if args.file:
        hosts = [line.strip() for line in args.file if line.strip()]
    elif args.hosts:
        hosts = args.hosts
    else:
        hosts = read_hosts_from_stdin(args.verbose)

    if not hosts:
        console.print("[bold red]No hosts specified.[/bold red]")
        sys.exit(1)

    total_hosts = len(hosts)

    start_time_connection_test = datetime.now()
    console.print(
        f"[bold cyan]Starting Connection Test at {start_time_connection_test.strftime('%Y-%m-%d %H:%M')}[/bold cyan]"
    )

    start_time_ping_sweep = datetime.now()
    console.print(
        f"[bold yellow]Stage 1 - Starting Ping Sweep at {start_time_ping_sweep.strftime('%Y-%m-%d %H:%M')}[/bold yellow]"
    )

    nm = nmap.PortScanner()
    up_hosts, down_hosts = perform_ping_sweep(nm, hosts, args.verbose)

    end_time_ping_sweep = datetime.now()
    duration_ping_sweep = (end_time_ping_sweep - start_time_ping_sweep).total_seconds()

    console.print(
        f"[bold yellow]Stage 1 - Ping sweep done: {total_hosts} hosts ({len(up_hosts)} hosts up) scanned in {duration_ping_sweep:.2f} seconds[/bold yellow]"
    )

    newly_up_hosts = []
    if down_hosts:
        start_time_port_scan = datetime.now()
        console.print(
            f"[bold magenta]Stage 2 - Starting Port Scan on unreachable hosts at {start_time_port_scan.strftime('%Y-%m-%d %H:%M')}[/bold magenta]"
        )

        newly_up_hosts = perform_sudo_port_scan(down_hosts, args.verbose)
        up_hosts.extend(newly_up_hosts)

        end_time_port_scan = datetime.now()
        duration_port_scan = (end_time_port_scan - start_time_port_scan).total_seconds()

        console.print(
            f"[bold magenta]Stage 2 - Port Scan done: {total_hosts} hosts ({len(up_hosts)} hosts up) scanned in {duration_port_scan:.2f} seconds[/bold magenta]"
        )

    end_time_connection_test = datetime.now()
    duration_connection_test = (
        end_time_connection_test - start_time_connection_test
    ).total_seconds()

    console.print(
        f"[bold cyan]Connection Test done: {total_hosts} hosts ({len(up_hosts)} hosts up) scanned in {duration_connection_test:.2f} seconds[/bold cyan]"
    )

    if args.md_table:
        table_lines_md = [
            "| Host | Reachable | Comment |",
            "|------|-----------|---------|",
        ]
        for host in hosts:
            status_md = "Yes" if host in up_hosts else "No"
            comment_md = (
                "Host does not respond to ICMP packets"
                if host in newly_up_hosts
                else ""
            )
            table_lines_md.append(f"| {host} | {status_md} | {comment_md} |")
        md_output = "\n".join(table_lines_md)
        print(md_output)
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Host", style="dim")
        table.add_column("Reachable")
        table.add_column("Comment")
        for host in hosts:
            status_console = (
                "[green]Yes[/green]" if host in up_hosts else "[red]No[/red]"
            )
            comment_console = (
                "Host does not respond to ICMP packets"
                if host in newly_up_hosts
                else ""
            )
            table.add_row(host, status_console, comment_console)
        console.print(table)


if __name__ == "__main__":
    main()
