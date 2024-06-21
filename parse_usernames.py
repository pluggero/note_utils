import argparse
import re


def extract_command_output(file_path, command, command_patterns):
    with open(file_path, "r") as file:
        content = file.read()

    pattern = command_patterns.get(command)
    if not pattern:
        print(f"No regex pattern defined for command: {command}")
        return None

    match = re.search(pattern, content, re.DOTALL)
    if match:
        command_output = match.group(1).strip()
        return command_output
    else:
        print(f"'{command}' command output could not be found in the file.")
        return None


def parse_users_get_localuser(command_output):
    lines = command_output.split("\n")

    user_lines = [
        line
        for line in lines[2:]
        if not line.startswith(" ") and not line.startswith("-")
    ]

    user_names = []
    for line in user_lines:
        parts = line.split()
        if parts:
            user_name = parts[0]
            user_names.append(user_name)

    return user_names


def parse_users_net_user(command_output):
    lines = command_output.split("\n")

    user_names = []
    for line in lines:
        if (
            line.startswith("User accounts for")
            or line.startswith("-")
            or "command completed successfully" in line
        ):
            continue

        parts = line.split()
        user_names.extend(parts)

    return user_names


def parse_users_net_user_domain(command_output):
    lines = command_output.split("\n")

    user_names = []
    for line in lines:
        if (
            line.startswith("User accounts for")
            or line.startswith("-")
            or "command completed successfully" in line
        ):
            continue

        parts = line.split()
        user_names.extend(parts)

    return user_names


def print_usernames(user_names, domain):
    if domain:
        user_names = [f"{domain}\\{user}" for user in user_names]
    for user in user_names:
        print(user)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Extract information from specified command output in a Markdown file."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "command",
        help=(
            "The command to search for in the Markdown file. Supported commands are:\n"
            "\t- get-localuser\n"
            "\t- net user\n"
            "\t- net user /domain"
        ),
    )
    parser.add_argument(
        "file_path",
        help="Path to the Markdown file containing the command output.",
    )
    parser.add_argument(
        "--add-domain",
        help="Domain name to prepend to the usernames.",
        default=None,
    )

    args = parser.parse_args()

    # Define regex patterns for each command
    command_patterns = {
        "get-localuser": rf"{re.escape('get-localuser')}.*?\n\n((?:.*?\n)*?)```",
        "net user": rf"{re.escape('net user')}(?! /domain).*?\n\n((?:.*?\n)*?)```",
        "net user /domain": rf"{re.escape('net user /domain')}.*?\n\n((?:.*?\n)*?)```",
    }

    command_output = extract_command_output(
        args.file_path, args.command, command_patterns
    )
    if command_output:
        if args.command == "get-localuser":
            user_names = parse_users_get_localuser(command_output)
        elif args.command == "net user":
            user_names = parse_users_net_user(command_output)
        elif args.command == "net user /domain":
            user_names = parse_users_net_user_domain(command_output)
        else:
            print(f"Parsing logic for {args.command} is not implemented yet.")
            return

        print_usernames(user_names, args.add_domain)


if __name__ == "__main__":
    main()
