#!/usr/bin/env python3

import argparse
import sys


def transform_usernames(usernames):
    return [f"**USER**: `{username}`" for username in usernames]


def main():
    parser = argparse.ArgumentParser(
        description="Transform a list of usernames into a specified format."
    )
    parser.add_argument(
        "input_file",
        type=argparse.FileType("r"),
        nargs="?",
        default=sys.stdin,
        help="File containing the list of usernames. Reads from stdin if not provided.",
    )

    args = parser.parse_args()

    usernames = [line.strip() for line in args.input_file if line.strip()]
    transformed_usernames = transform_usernames(usernames)

    for username in transformed_usernames:
        print(username)


if __name__ == "__main__":
    main()
