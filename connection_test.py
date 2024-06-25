#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys

import nmap


def check_sudo():
    if os.geteuid() != 0:
        print("This script must be run with sudo privileges.")
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
    return parser


def read_hosts_from_stdin(verbose):
    if verbose:
        print(
            "Reading hosts from stdin. Press Ctrl+D (or Ctrl+Z on Windows) to end input."
        )
    return [line.strip() for line in sys.stdin if line.strip()]


def perform_ping_sweep(nm, hosts, verbose=False):
    up_hosts = []
    down_hosts = []

    if verbose:
        print("\nPerforming ping sweep...")
    for host in hosts:
        if verbose:
            print(f"Pinging {host}...")
        try:
            nm.scan(host, arguments="-sn")
            if nm.all_hosts():
                if verbose:
                    print(f"{host} is up.")
                up_hosts.append(host)
            else:
                if verbose:
                    print(f"{host} is down.")
                down_hosts.append(host)
        except Exception as e:
            if verbose:
                print(f"Error scanning {host}: {e}")
            down_hosts.append(host)

    return up_hosts, down_hosts


def perform_sudo_port_scan(host, verbose=False):
    try:
        if verbose:
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
        if verbose:
            print(f"Error scanning ports on {host}: {e}")
        return []


def main():
    check_sudo()

    parser = parse_arguments()
    args = parser.parse_args()

    if args.file:
        hosts = [line.strip() for line in args.file if line.strip()]
    elif args.hosts:
        hosts = args.hosts
    else:
        hosts = read_hosts_from_stdin(args.verbose)

    if not hosts:
        parser.print_help()
        sys.exit(1)

    nm = nmap.PortScanner()
    up_hosts, down_hosts = perform_ping_sweep(nm, hosts, args.verbose)

    confirmed_up_hosts = []
    if down_hosts:
        for host in down_hosts:
            open_ports = perform_sudo_port_scan(host, args.verbose)
            if open_ports:
                confirmed_up_hosts.append(host)

    all_up_hosts = up_hosts + confirmed_up_hosts

    print("\nHosts that are online:")
    for host in all_up_hosts:
        print(host)

    print("\nHosts that are not online:")
    for host in set(hosts) - set(all_up_hosts):
        print(host)


if __name__ == "__main__":
    main()
