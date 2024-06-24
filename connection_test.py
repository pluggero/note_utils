import argparse
import os
import subprocess
import sys

import nmap


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
    return parser


def read_hosts_from_stdin():
    print("Reading hosts from stdin. Press Ctrl+D (or Ctrl+Z on Windows) to end input.")
    return [line.strip() for line in sys.stdin if line.strip()]


def perform_ping_sweep(nm, hosts):
    up_hosts = []
    down_hosts = []

    print("\nPerforming ping sweep...")
    for host in hosts:
        print(f"Pinging {host}...")
        try:
            nm.scan(host, arguments="-sn")
            if nm.all_hosts():
                print(f"{host} is up.")
                up_hosts.append(host)
            else:
                print(f"{host} is down.")
                down_hosts.append(host)
        except Exception as e:
            print(f"Error scanning {host}: {e}")
            down_hosts.append(host)

    return up_hosts, down_hosts


def perform_sudo_port_scan(host):
    try:
        print(f"Scanning top 1000 ports on {host} with sudo nmap -Pn...")
        result = subprocess.run(
            ["sudo", "nmap", "-Pn", "--top-ports", "1000", host],
            capture_output=True,
            text=True,
            check=True,
        )
        open_ports = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0]
                open_ports.append(port)
        return open_ports
    except subprocess.CalledProcessError as e:
        print(f"Error scanning ports on {host}: {e}")
        return []


def main():
    parser = parse_arguments()
    args = parser.parse_args()

    if args.file:
        hosts = [line.strip() for line in args.file if line.strip()]
    elif args.hosts:
        hosts = args.hosts
    else:
        hosts = read_hosts_from_stdin()

    if not hosts:
        parser.print_help()
        sys.exit(1)

    nm = nmap.PortScanner()
    up_hosts, down_hosts = perform_ping_sweep(nm, hosts)

    print("\nHosts that are up based on ping sweep:")
    for host in up_hosts:
        print(host)

    confirmed_up_hosts = []
    if down_hosts:
        for host in down_hosts:
            open_ports = perform_sudo_port_scan(host)
            if open_ports:
                confirmed_up_hosts.append(host)

    print(
        "\nConfirmed hosts that are up (either responded to ping or have open ports):"
    )
    for host in up_hosts + confirmed_up_hosts:
        print(host)


if __name__ == "__main__":
    main()
