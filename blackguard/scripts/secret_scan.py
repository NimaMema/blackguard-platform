"""Minimal dependency-free secret scanner for CI and pre-commit use.

Flags likely credentials in tracked files. Intentional test fixtures can be
allow-listed with the marker comment `secret-scan: allow` on the same line.
"""

import re
import subprocess
import sys

PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "BLACKGUARD agent credential": re.compile(r"\bbga_[A-Za-z0-9_-]{30,}"),
    "BLACKGUARD session token": re.compile(r"\bbgs_[A-Za-z0-9_-]{30,}"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "generic assignment": re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9/+_=-]{24,}['\"]"),
}
SKIP = (".png", ".jpg", ".svg", ".sqlite3", ".ico")


def main():
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    findings = []
    for path in files:
        if path.endswith(SKIP):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                for number, line in enumerate(handle, 1):
                    if "secret-scan: allow" in line:
                        continue
                    for name, pattern in PATTERNS.items():
                        if pattern.search(line):
                            findings.append(f"{path}:{number}: possible {name}")
        except OSError:
            continue
    if findings:
        print("Possible secrets found:\n" + "\n".join(findings))
        return 1
    print(f"Secret scan clean ({len(files)} tracked files).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
