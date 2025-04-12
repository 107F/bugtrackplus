import re


class InvalidBugError(Exception):
    """
    Custom exception raised when a bug report's field fails validation,
    such as when the target domain is not properly formatted.
    """

    pass


class BugReport:
    """
    Represents a bug bounty report containing information about a target, endpoint, vulnerability type, and severity.

    Validates the `target` field using a regular expression and normalizes the `severity` field to lowercase.

    :param target: The domain name of the target (e.g., "example.com").
    :type target: str
    :param endpoint: The path where the vulnerability was found (e.g., "/login").
    :type endpoint: str
    :param vuln_type: Type of the vulnerability (e.g., "XSS", "SQLi").
    :type vuln_type: str
    :param severity: Severity level of the bug ("low", "medium", "high", "critical").
    :type severity: str
    :raises InvalidBugError: If the target domain does not match the required format.
    """

    VALID_SEVERITIES = {"low", "medium", "high", "critical"}

    def __init__(self, target: str, endpoint: str, vuln_type: str, severity: str):
        self.target = target
        self.endpoint = endpoint
        self.vuln_type = vuln_type
        self.severity = severity.lower()

    @property
    def target(self) -> str:
        """
        Gets the validated target domain.

        :return: The domain name of the target.
        :rtype: str
        """
        return self._target

    @target.setter
    def target(self, value: str):
        """
        Validates and sets the target domain using a regular expression.

        :param value: The domain name to validate.
        :type value: str
        :raises InvalidBugError: If the domain does not match the expected format.
        """
        if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            raise InvalidBugError("Invalid target format.")
        self._target = value

    def to_dict(self) -> dict:
        """
        Converts the bug report instance into a dictionary.

        :return: Dictionary containing bug report fields.
        :rtype: dict
        """
        return {
            "target": self.target,
            "endpoint": self.endpoint,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
        }

    def __str__(self) -> str:
        """
        Returns a formatted string representation of the bug report.

        :return: String describing the bug report in a concise format.
        :rtype: str
        """
        return f"[{self.severity.upper()}] {self.vuln_type} at {self.target}{self.endpoint}"
