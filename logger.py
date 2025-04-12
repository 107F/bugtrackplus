import csv


def bug_logger(filename: str):
    """
    Coroutine that logs bug report dictionaries to a CSV file.

    This function opens the specified CSV file in append mode and initializes a `csv.DictWriter`
    using fixed fieldnames: `["target", "endpoint", "vuln_type", "severity"]`.
    It then waits for input via `send()` and writes each dictionary entry to the file.
    The coroutine must be primed by calling `next()` before use.

    :param filename: The path to the CSV file to which bug reports will be logged.
    :type filename: str
    :yields: Accepts bug report dictionaries using `.send()`.
    :raises ValueError: If the dictionary passed does not conform to the expected fieldnames.
    :return: This is a coroutine and does not return a value.
    :rtype: None
    :example:

    >>> logger = bug_logger("bugs.csv")
    >>> next(logger)  # Prime the coroutine
    >>> logger.send({"target": "example.com", "endpoint": "/", "vuln_type": "XSS", "severity": "low"})
    >>> logger.close()
    """
    with open(filename, "a", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["target", "endpoint", "vuln_type", "severity"]
        )
        writer.writeheader()
        try:
            while True:
                bug = yield
                writer.writerow(bug)
        finally:
            print("[Logger] Logger closed.")
