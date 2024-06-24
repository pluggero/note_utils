import argparse
import sys

import nmap


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Perform an Nmap ping sweep on given hosts."
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


def perform_ping_sweep(hosts):
    nm = nmap.PortScanner()
    up_hosts = []
    down_hosts = []

    for host in hosts:
        try:
            nm.scan(host, arguments="-sn")
            if nm.all_hosts():
                up_hosts.append(host)
            else:
                down_hosts.append(host)
        except Exception as e:
            print(f"Error scanning {host}: {e}")
            down_hosts.append(host)

    return up_hosts, down_hosts


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

    up_hosts, down_hosts = perform_ping_sweep(hosts)

    print("\nHosts that are up:")
    for host in up_hosts:
        print(host)

    print("\nHosts that cannot be accessed:")
    for host in down_hosts:
        print(host)


if __name__ == "__main__":
    main()
