#!/usr/bin/env python3

import argparse
import os
import socket
import subprocess
import sys
from datetime import datetime

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
    parser.add_argument(
        "--web-test",
        action="store_true",
        help="Test web connectivity on ports 80 and 443",
    )
    parser.add_argument(
        "--web-ports",
        type=str,
        help="Comma-separated list of custom ports to test (e.g., '80,443,8080')",
    )
    return parser.parse_args()


def read_hosts_from_stdin(verbose):
    if verbose:
        console.print(
            "Reading hosts from stdin. Press Ctrl+D (or Ctrl+Z on Windows) to end input."
        )
    return [line.strip() for line in sys.stdin if line.strip()]


def perform_ping_sweep(hosts, verbose=False):
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
                result = subprocess.run(
                    ["sudo", "nmap", "-sn", host],
                    capture_output=True,
                    text=True,
                )
                if "Host is up" in result.stdout:
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


def perform_port_scan(hosts, verbose=False):
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


def perform_web_connectivity_test(hosts, ports=[80, 443], verbose=False):
    web_results = {}
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[blue]Testing web connectivity...", total=len(hosts))

        for host in hosts:
            web_results[host] = {}
            for port in ports:
                try:
                    if verbose:
                        console.print(f"Testing {host}:{port}...")
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((host, port))
                    sock.close()
                    web_results[host][str(port)] = "Open"
                except socket.timeout:
                    web_results[host][str(port)] = "Timeout"
                except ConnectionRefusedError:
                    web_results[host][str(port)] = "Connection Refused"
                except socket.gaierror:
                    web_results[host][str(port)] = "DNS Error"
                except Exception as e:
                    if verbose:
                        console.print(f"[red]Error testing {host}:{port}: {e}[/red]")
                    web_results[host][str(port)] = "Unknown Error"
            progress.advance(task)

    return web_results


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

    up_hosts, down_hosts = perform_ping_sweep(hosts, args.verbose)

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

        newly_up_hosts = perform_port_scan(down_hosts, args.verbose)
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

    # Web connectivity test
    web_results = {}
    web_ports = [80, 443]
    if args.web_test:
        if args.web_ports:
            try:
                web_ports = [int(port.strip()) for port in args.web_ports.split(",")]
            except ValueError:
                console.print("[bold red]Error: Invalid port format. Use comma-separated integers (e.g., '80,443,8080')[/bold red]")
                sys.exit(1)
        
        start_time_web_test = datetime.now()
        console.print(
            f"[bold green]Stage 3 - Starting Web Connectivity Test at {start_time_web_test.strftime('%Y-%m-%d %H:%M')}[/bold green]"
        )
        web_results = perform_web_connectivity_test(up_hosts, web_ports, args.verbose)
        end_time_web_test = datetime.now()
        duration_web_test = (end_time_web_test - start_time_web_test).total_seconds()
        console.print(
            f"[bold green]Stage 3 - Web Connectivity Test done: {len(up_hosts)} hosts tested on {len(web_ports)} ports in {duration_web_test:.2f} seconds[/bold green]"
        )

    console.print(
        f"[bold cyan]Connection Test done: {total_hosts} hosts ({len(up_hosts)} hosts up) scanned in {duration_connection_test:.2f} seconds[/bold cyan]"
    )

    # Show the rendered result table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Host", style="dim")
    table.add_column("Reachable")
    table.add_column("Comment")
    if args.web_test:
        for port in web_ports:
            table.add_column(f"Port {port}")
    
    for host in hosts:
        status_console = "[green]Yes[/green]" if host in up_hosts else "[red]No[/red]"
        comment_console = "No ICMP Echo Reply" if host in newly_up_hosts else ""
        
        if args.web_test:
            row_data = [host, status_console, comment_console]
            for port in web_ports:
                port_status = web_results.get(host, {}).get(str(port), "N/A") if host in up_hosts else "N/A"
                row_data.append(port_status)
            table.add_row(*row_data)
        else:
            table.add_row(host, status_console, comment_console)
    console.print(table)

    # Only shows the markdown table if the flag is set
    if args.md_table:
        if args.web_test:
            # Create dynamic header with port columns
            port_headers = " | ".join([f"Port {port}" for port in web_ports])
            header_line = f"| Host | Reachable | Comment | {port_headers} |"
            separator_line = "|------|-----------|---------|" + "|-----------|" * len(web_ports)
            
            table_lines_md = [header_line, separator_line]
            
            for host in hosts:
                status_md = "Yes" if host in up_hosts else "No"
                comment_md = "No ICMP Echo Reply" if host in newly_up_hosts else ""
                port_statuses = []
                for port in web_ports:
                    port_status = web_results.get(host, {}).get(str(port), "N/A") if host in up_hosts else "N/A"
                    port_statuses.append(port_status)
                port_data = " | ".join(port_statuses)
                table_lines_md.append(f"| {host} | {status_md} | {comment_md} | {port_data} |")
        else:
            table_lines_md = [
                "| Host | Reachable | Comment |",
                "|------|-----------|---------|",
            ]
            for host in hosts:
                status_md = "Yes" if host in up_hosts else "No"
                comment_md = "No ICMP Echo Reply" if host in newly_up_hosts else ""
                table_lines_md.append(f"| {host} | {status_md} | {comment_md} |")
        md_output = "\n".join(table_lines_md)
        print(f"\n{md_output}")


if __name__ == "__main__":
    main()
