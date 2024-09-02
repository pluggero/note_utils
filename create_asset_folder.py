#!/usr/bin/env python3

import argparse
import os
import sys


def create_folders_from_file(file_path, base_path):
    try:
        with open(file_path, "r") as file:
            hostnames = [line.strip() for line in file.readlines()]
            create_folders(hostnames, base_path)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")


def create_folders_from_stdin(base_path):
    hostnames = [line.strip() for line in sys.stdin.read().splitlines()]
    create_folders(hostnames, base_path)


def create_folders(hostnames, base_path):
    for hostname in hostnames:
        folder_path = os.path.join(base_path, hostname)
        try:
            os.makedirs(folder_path, exist_ok=True)
            print(f"Created folder: {folder_path}")
        except Exception as e:
            print(f"Error creating folder {folder_path}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Create folders for each hostname in a specified path.",
        usage="%(prog)s [-f FILE] -p [PATH]\n       cat hostnames.txt | %(prog)s -p [PATH]",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Path to the file containing hostnames or DNS names.",
    )
    parser.add_argument(
        "-p",
        "--path",
        type=str,
        default=os.getcwd(),
        help="Base path where folders should be created. Defaults to the current directory.",
    )

    args = parser.parse_args()

    if not args.file and sys.stdin.isatty() and not args.path:
        parser.print_help(sys.stderr)
        sys.exit(1)

    base_path = args.path if args.path else os.getcwd()

    if args.file:
        create_folders_from_file(args.file, base_path)
    else:
        create_folders_from_stdin(base_path)


if __name__ == "__main__":
    main()
