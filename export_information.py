#!/usr/bin/env python3

import argparse
import os
import re


def extract_information(file_path, patterns, with_domain=False):
    """Extract information from the file content based on provided patterns."""
    with open(file_path, "r") as file:
        content = file.read()
        items = []
        domain_pattern = r"\\([^\\]+)$"

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # If extracting usernames and the --with-domain flag is not set, strip the domain
                if not with_domain and "\\" in match:
                    match = re.search(domain_pattern, match).group(1)
                match = match.strip()
                # Ensure uniqueness
                if match not in items:
                    items.append(match)

        return items


def get_patterns(info_type):
    """Return the appropriate patterns based on the type of information to extract."""
    return {
        "username": [
            r"\*\*CREDENTIALS\*\*: ```([^:]+):",  # Matches usernames in the CREDENTIALS line
            r"\*\*HASH\*\*: ```([^:]+):",  # Matches usernames in the HASH line
            r"\*\*USER\*\*: ```([^ |^`]+)",  # Matches usernames in the USER line
        ],
        "password": [
            r"\*\*CREDENTIALS\*\*: ```[^:]+:([^ |^`]+)",  # Matches passwords in the CREDENTIALS line
            r"\*\*PASSWORD\*\*: ```([^ |^`]+)",  # Matches passwords in the PASSWORD line
        ],
    }[info_type]


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract usernames or passwords from notes."
    )
    parser.add_argument(
        "type",
        choices=["username", "password"],
        help="Type of information to extract (username or password)",
    )
    parser.add_argument(
        "--with-domain",
        action="store_true",
        help="Include domain in the usernames (only applies to username type)",
    )
    parser.add_argument(
        "note_path",
        help="Path to the note file or folder containing note files",
    )

    return parser.parse_args()


def collect_files(note_path):
    """Collects files from a given path, which can be either a single file or a directory."""
    if os.path.isfile(note_path):
        return [note_path]
    elif os.path.isdir(note_path):
        return [
            os.path.join(note_path, f)
            for f in os.listdir(note_path)
            if os.path.isfile(os.path.join(note_path, f))
        ]
    else:
        raise ValueError(f"Invalid path: {note_path}")


def main():
    args = parse_arguments()
    patterns = get_patterns(args.type)
    items = set()

    # Collect files from the provided path
    note_files = collect_files(args.note_path)

    # Iterate through each file and extract information
    for file_path in sorted(note_files):
        extracted_items = extract_information(file_path, patterns, args.with_domain)
        items.update(extracted_items)

    # Output the unique usernames or passwords, one per line
    for item in sorted(items):
        print(item)


if __name__ == "__main__":
    main()
