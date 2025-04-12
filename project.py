import argparse
from bug import BugReport, InvalidBugError
from logger import bug_logger


def validate_severity(severity: str) -> str:
    """
    Validates the severity level of a bug report.

    Converts the input to lowercase and checks if it is within the accepted severity levels.
    Raises a ValueError if the severity level is not recognized.

    :param severity: The input severity level (case-insensitive).
    :type severity: str
    :raises ValueError: If the provided severity level is not in the set {"low", "medium", "high", "critical"}.
    :return: The validated severity string in lowercase.
    :rtype: str
    """
    valid = {"low", "medium", "high", "critical"}
    severity = severity.lower()
    if severity not in valid:
        raise ValueError("Invalid severity level.")
    return severity


def prompt_input(prompt: str) -> str:
    """
    Prompts the user for input and strips any leading/trailing whitespace.

    :param prompt: The message displayed to the user.
    :type prompt: str
    :return: The user's input with whitespace removed.
    :rtype: str
    """
    return input(prompt).strip()


def make_bug_data(args) -> dict:
    """
    Constructs a dictionary representing a bug report using command-line arguments.

    Defaults are applied where optional arguments are omitted. The severity is validated.

    :param args: Parsed command-line arguments.
    :type args: argparse.Namespace
    :raises ValueError: If severity is invalid.
    :return: A dictionary containing bug report data.
    :rtype: dict
    """
    return {
        "target": args.target,
        "endpoint": args.endpoint or "/",
        "vuln_type": args.vuln_type or "Unknown",
        "severity": validate_severity(args.severity or "low"),
    }


def main():
    """
    Entry point for the BugTrack+ CLI application.

    Parses command-line arguments, and if logging mode is enabled,
    initializes the coroutine logger, validates bug data, and writes it to a CSV file.
    Handles exceptions for invalid domain format and invalid severity levels.

    :raises InvalidBugError: If the target domain format is invalid.
    :raises ValueError: If the severity level is not recognized.
    """
    parser = argparse.ArgumentParser(description="Log bug bounty reports.")
    parser.add_argument("--log", action="store_true", help="Enable logging mode")
    parser.add_argument("--target", help="Target domain (e.g., example.com)")
    parser.add_argument("--endpoint", help="Vulnerable endpoint path (e.g., /login)")
    parser.add_argument("--vuln_type", help="Type of vulnerability (e.g., XSS, SQLi)")
    parser.add_argument(
        "--severity", help="Severity level: low, medium, high, or critical"
    )
    args = parser.parse_args()

    if args.log:
        logger = bug_logger("bugs.csv")
        next(logger)  # Prime the coroutine
        try:
            bug = make_bug_data(args)
            logger.send(bug)
        except (InvalidBugError, ValueError) as e:
            print("Error:", e)
        finally:
            logger.close()


if __name__ == "__main__":
    main()
