import pytest
from bug import BugReport, InvalidBugError
from logger import bug_logger
from project import validate_severity
import os


def test_bugreport_creation():
    """
    Test that a BugReport instance is correctly created.

    Checks that the `severity` attribute is normalized to lowercase,
    regardless of the input casing.

    :raises AssertionError: If severity is not properly normalized.
    """
    bug = BugReport("example.com", "/login", "XSS", "High")
    assert bug.severity == "high"


def test_invalid_target():
    """
    Test that BugReport raises InvalidBugError for an invalid domain format.

    Ensures that the custom validation logic using regex is enforced.

    :raises InvalidBugError: When domain does not match the regex.
    """
    with pytest.raises(InvalidBugError):
        BugReport("not-a-domain", "/", "SQLi", "medium")


def test_logger_writes(tmp_path):
    """
    Test that the coroutine-based bug_logger writes to a CSV file correctly.

    Creates a temporary CSV file, sends a valid bug dictionary via coroutine,
    and asserts that the file has more than one line (i.e., header + one entry).

    :param tmp_path: Pytest fixture that provides a temporary directory unique to the test run.
    :type tmp_path: pathlib.Path
    :raises AssertionError: If the log file is empty or malformed.
    """
    log = bug_logger(tmp_path / "test.csv")
    next(log)
    log.send(
        {"target": "test.com", "endpoint": "/", "vuln_type": "XSS", "severity": "low"}
    )
    log.close()
    with open(tmp_path / "test.csv") as f:
        lines = f.readlines()
        assert len(lines) > 1  # Header + 1 entry


def test_validate_severity():
    """
    Test that the validate_severity function accepts valid severities
    and raises a ValueError for invalid input.

    :raises AssertionError: If valid input is rejected or invalid input is accepted.
    :raises ValueError: Expected for invalid severity levels.
    """
    assert validate_severity("low") == "low"
    with pytest.raises(ValueError):
        validate_severity("invalid")
