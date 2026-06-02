#!/usr/bin/env python3

import argparse
import sys


def format_user(item, domain=None):
    prefix = f"{domain.lower()}\\" if domain and "\\" not in item else ""
    return f"- **USER**: ```{prefix}{item}```"


def get_formatter(info_type):
    """Return the formatting function based on the type of information to import."""
    return {
        "user": format_user,
        # "password": format_password,
        # "hash": format_hash,
        # "tgt": format_tgt,
    }[info_type]


def read_items(input_file):
    """Read non-blank lines from the input file."""
    return [line.strip().lower() for line in input_file if line.strip()]


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Format items into note entries for import."
    )
    parser.add_argument(
        "type",
        choices=["user"],
        help="Type of information to import (user)",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default=None,
        help="Prepend domain to each username, e.g. CORP (only applies to user type)",
    )
    parser.add_argument(
        "input_file",
        type=argparse.FileType("r"),
        nargs="?",
        default=sys.stdin,
        help="File containing one item per line. Reads from stdin if not provided.",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()
    formatter = get_formatter(args.type)
    items = set(read_items(args.input_file))

    kwargs = {}
    if args.type == "user":
        kwargs["domain"] = args.domain

    for item in sorted(items):
        print(formatter(item, **kwargs))


if __name__ == "__main__":
    main()
