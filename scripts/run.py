#!/usr/bin/env python3
"""Lint bash scripts for common mistakes, security issues, and style violations."""

import json
import re
import sys
from pathlib import Path

CHECKS = [
    # (pattern, severity, message, fix)
    (r'\$\w+(?!\w)', "warning", "Unquoted variable expansion", "Wrap in double quotes: \"$var\""),
    (r'\$\{[^}]+\}(?!")', "warning", "Unquoted variable expansion with braces", "Wrap in double quotes: \"${var}\""),
    (r'^\s*cd\s+[^"\'&|;\n]+\s*$', "warning", "cd without error handling", "Use cd ... || exit 1"),
    (r'\beval\b', "error", "Use of eval is a security risk", "Avoid eval; use arrays or other safe alternatives"),
    (r'mktemp\b(?!.*-d)', "info", "Consider using mktemp -d for temp directories", "Use mktemp -d for directory creation"),
    (r'/tmp/[a-zA-Z]', "error", "Hardcoded /tmp path is insecure", "Use mktemp instead of hardcoded /tmp paths"),
    (r'^\s*#!/bin/sh\b', "info", "Script uses /bin/sh — ensure POSIX compatibility", "Use #!/usr/bin/env bash if bash features are needed"),
    (r'\bfunction\s+\w+\b(?!\s*\()', "info", "function keyword without parentheses is non-POSIX", "Use name() { instead of function name {"),
    (r'(?<!\bset\s)-[euo]\s+pipefail|set\s+-euo\s+pipefail', "skip", "", ""),
    (r'\[\[\s', "info", "[[ is a bash extension, not POSIX", "Use [ for POSIX compatibility or ensure #!/bin/bash"),
    (r'>\s*/dev/null\s+2>&1', "info", "Consider using &>/dev/null for brevity", "Use &>/dev/null (bash only)"),
    (r'\bchmod\s+777\b', "error", "chmod 777 gives everyone full access", "Use more restrictive permissions like 755 or 700"),
    (r'\bcurl\b.*(?!\s+-[sf])', "warning", "curl without -f flag won't detect HTTP errors", "Add -f to fail on HTTP errors"),
    (r'(?:^|\s)rm\s+-rf\s+[/"]', "error", "Dangerous rm -rf with absolute or quoted path", "Verify path before rm -rf; use variable with safety check"),
    (r'^\s*source\s+', "info", "source is not POSIX; use . instead", "Replace source with . (dot) for POSIX compatibility"),
]

# Patterns that should not trigger unquoted variable checks
SAFE_CONTEXTS = [
    r'"\$',          # Already quoted
    r"'\$",          # In single quotes (literal)
    r'\$\(',         # Command substitution
    r'\$\(\(',       # Arithmetic
    r'\$\{.*:-',     # Default value
]


def lint_line(line: str, lineno: int, filepath: str, min_severity: str) -> list[dict]:
    issues = []
    severity_order = {"info": 0, "warning": 1, "error": 2}
    min_level = severity_order.get(min_severity, 0)

    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return issues

    for pattern, severity, message, fix in CHECKS:
        if severity == "skip":
            continue
        if severity_order.get(severity, 0) < min_level:
            continue
        # Special handling for unquoted variables - skip if in quotes
        if "Unquoted variable" in message:
            # Check if the variable is already inside double quotes
            if re.search(r'"[^"]*\$\w+[^"]*"', line) or re.search(r'"[^"]*\$\{[^}]+\}[^"]*"', line):
                continue
            # Skip if in single quotes
            if re.search(r"'[^']*\$[^']*'", line):
                continue
            # Skip assignments like VAR=$other
            if re.match(r'^\s*\w+=\$', stripped):
                continue
            # Skip inside $(...)
            if re.search(r'\$\([^)]*\$\w+', line):
                continue
        match = re.search(pattern, line)
        if match:
            issues.append({
                "file": filepath,
                "line": lineno,
                "severity": severity,
                "message": message,
                "fix": fix,
                "matched": match.group(0).strip()
            })
    return issues


def check_file_level(lines: list[str], filepath: str, min_severity: str) -> list[dict]:
    """Check file-level issues."""
    issues = []
    severity_order = {"info": 0, "warning": 1, "error": 2}
    min_level = severity_order.get(min_severity, 0)

    content = "\n".join(lines)

    # Check for shebang
    if lines and not lines[0].startswith("#!"):
        if severity_order["warning"] >= min_level:
            issues.append({
                "file": filepath, "line": 1, "severity": "warning",
                "message": "Missing shebang line", "fix": "Add #!/usr/bin/env bash as the first line",
                "matched": ""
            })

    # Check for set -e or set -euo pipefail
    if "set -e" not in content and "set -euo pipefail" not in content:
        if severity_order["warning"] >= min_level:
            issues.append({
                "file": filepath, "line": 1, "severity": "warning",
                "message": "No set -e for error handling",
                "fix": "Add set -euo pipefail near the top of the script",
                "matched": ""
            })

    return issues


def lint_file(filepath: str, min_severity: str = "info") -> list[dict]:
    path = Path(filepath)
    if not path.exists():
        return [{"file": filepath, "line": 0, "severity": "error",
                 "message": f"File not found: {filepath}", "fix": "", "matched": ""}]

    lines = path.read_text().splitlines()
    issues = check_file_level(lines, filepath, min_severity)

    for i, line in enumerate(lines, 1):
        issues.extend(lint_line(line, i, filepath, min_severity))

    return issues


def format_text(issues: list[dict]) -> str:
    lines = []
    for issue in issues:
        lines.append(f"{issue['file']}:{issue['line']}: [{issue['severity']}] {issue['message']} (fix: {issue['fix']})")
    errors = sum(1 for i in issues if i["severity"] == "error")
    warnings = sum(1 for i in issues if i["severity"] == "warning")
    infos = sum(1 for i in issues if i["severity"] == "info")
    lines.append(f"\n{len(issues)} issues found ({errors} errors, {warnings} warnings, {infos} info)")
    return "\n".join(lines)


def main():
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print("Usage: run.py [OPTIONS] FILE [FILE...]")
        print()
        print("Lint shell scripts for common mistakes and security issues.")
        print()
        print("Options:")
        print("  --severity LEVEL  Minimum severity: info, warning, error (default: info)")
        print("  --format FORMAT   Output format: text or json (default: text)")
        print("  -h, --help        Show this help message")
        sys.exit(0)

    min_severity = "info"
    fmt = "text"
    files = []

    i = 0
    while i < len(args):
        if args[i] == "--severity" and i + 1 < len(args):
            min_severity = args[i + 1]; i += 2
        elif args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2
        else:
            files.append(args[i]); i += 1

    if not files:
        print("Error: at least one script file is required.", file=sys.stderr)
        sys.exit(2)

    all_issues = []
    for f in files:
        all_issues.extend(lint_file(f, min_severity))

    if fmt == "json":
        print(json.dumps(all_issues, indent=2))
    else:
        print(format_text(all_issues))

    has_errors = any(i["severity"] == "error" for i in all_issues)
    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
