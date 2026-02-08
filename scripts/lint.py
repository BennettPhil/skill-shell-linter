#!/usr/bin/env python3
"""Shell script linter: checks bash scripts for common mistakes, security issues, and style violations."""

import argparse
import json
import os
import re
import sys

# Severity levels (numeric for filtering)
SEVERITY_LEVELS = {"error": 0, "warning": 1, "info": 2}


class Finding:
    """Represents a single lint finding."""

    def __init__(self, filepath, line_num, severity, rule_id, message, fix):
        self.filepath = filepath
        self.line_num = line_num
        self.severity = severity
        self.rule_id = rule_id
        self.message = message
        self.fix = fix

    def to_dict(self):
        return {
            "line": self.line_num,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "message": self.message,
            "fix": self.fix,
        }

    def to_text(self):
        sev = self.severity.upper()
        return f"{self.filepath}:{self.line_num}: [{self.rule_id}] {sev}: {self.message} - {self.fix}"


def check_shebang(filepath, lines):
    """E001: Missing shebang line."""
    findings = []
    if not lines:
        findings.append(Finding(
            filepath, 1, "error", "E001",
            "Missing or incorrect shebang",
            "Add '#!/usr/bin/env bash' as the first line"
        ))
        return findings
    first = lines[0].rstrip("\n")
    if not (first.startswith("#!/bin/bash") or first.startswith("#!/usr/bin/env bash")):
        findings.append(Finding(
            filepath, 1, "error", "E001",
            "Missing or incorrect shebang",
            "Add '#!/usr/bin/env bash' as the first line"
        ))
    return findings


def check_error_handling(filepath, lines):
    """E005: Missing set -e or set -euo pipefail."""
    findings = []
    if not lines:
        return findings
    full_text = "\n".join(lines)
    # Look for set -e, set -euo pipefail, set -eu, set -o errexit, etc.
    has_error_handling = bool(re.search(r'^\s*set\s+.*-[A-Za-z]*e', full_text, re.MULTILINE))
    if not has_error_handling:
        findings.append(Finding(
            filepath, 1, "error", "E005",
            "No error handling found (missing 'set -e' or 'set -euo pipefail')",
            "Add 'set -euo pipefail' near the top of the script"
        ))
    return findings


def check_unquoted_variable(filepath, line_num, line):
    """E002: Unquoted variable expansion."""
    findings = []
    stripped = line.strip()

    # Skip comments
    if stripped.startswith("#"):
        return findings

    # Skip lines inside [[ ]] - find all text outside [[ ]]
    # Also skip arithmetic $(( )) and (( ))
    # Strategy: remove [[ ... ]], $(( ... )), (( ... )) contents, then check remainder

    check_line = line

    # Remove contents of [[ ... ]]
    check_line = re.sub(r'\[\[.*?\]\]', '', check_line)
    # Remove contents of $(( ... ))
    check_line = re.sub(r'\$\(\(.*?\)\)', '', check_line)
    # Remove contents of (( ... ))
    check_line = re.sub(r'\(\(.*?\)\)', '', check_line)
    # Remove quoted strings (double and single)
    check_line = re.sub(r'"[^"]*"', '', check_line)
    check_line = re.sub(r"'[^']*'", '', check_line)

    # Now look for unquoted $VAR or ${VAR}
    # But skip assignments like VAR=$other, VAR=${other}
    # Also skip $(), $?, $!, $$, $#, $@, $*, $0-$9, and $( (command sub)
    # Pattern: find $VAR or ${VAR} that are NOT part of an assignment (preceded by = without space)

    # Find all variable references in the remaining text
    for match in re.finditer(r'(?<!=)\$(\{[A-Za-z_][A-Za-z_0-9]*\}|[A-Za-z_][A-Za-z_0-9]*)', check_line):
        var_ref = match.group(0)
        pos = match.start()

        # Check if this is on the right side of an assignment (= immediately before $)
        if pos > 0 and check_line[pos - 1] == '=':
            continue

        # Check if preceded by += 
        if pos > 1 and check_line[pos - 2:pos] == '+=':
            continue

        findings.append(Finding(
            filepath, line_num, "error", "E002",
            f"Unquoted variable expansion '{var_ref}'",
            f"Quote it: \"{var_ref}\""
        ))
        # Only report once per line to reduce noise
        break

    return findings


def check_eval(filepath, line_num, line):
    """E003: Use of eval."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings
    # Match eval as a command (word boundary)
    if re.search(r'\beval\b', stripped):
        findings.append(Finding(
            filepath, line_num, "error", "E003",
            "Use of 'eval' is a security risk",
            "Refactor to avoid eval; use arrays for dynamic commands"
        ))
    return findings


def check_backticks(filepath, line_num, line):
    """E004: Backtick command substitution."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings
    if '`' in stripped:
        # Make sure it's actually a backtick substitution (paired backticks)
        count = stripped.count('`')
        if count >= 2:
            findings.append(Finding(
                filepath, line_num, "error", "E004",
                "Backtick command substitution",
                "Use $() instead of backticks for command substitution"
            ))
    return findings


def check_unsafe_temp(filepath, line_num, line):
    """W001: Unsafe temp file creation."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings
    # Match direct /tmp/ usage in assignments or redirection, but not mktemp
    if re.search(r'/tmp/[A-Za-z_0-9]', stripped) and 'mktemp' not in stripped:
        findings.append(Finding(
            filepath, line_num, "warning", "W001",
            "Unsafe temp file using hardcoded /tmp path",
            "Use mktemp: tmpfile=$(mktemp)"
        ))
    return findings


def check_cd_no_check(filepath, line_num, line):
    """W002: cd without error check."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings
    # Match bare cd commands not followed by || or && and not inside if/while
    if re.search(r'\bcd\b', stripped):
        # Skip if it has error handling
        if '||' in stripped or '&&' in stripped:
            return findings
        # Skip if inside if/while condition
        if stripped.startswith(('if ', 'while ', 'elif ')):
            return findings
        findings.append(Finding(
            filepath, line_num, "warning", "W002",
            "'cd' without error check",
            "Use 'cd <dir> || exit 1' or wrap in an if statement"
        ))
    return findings


def check_useless_cat(filepath, line_num, line):
    """W003: Useless use of cat."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings
    if re.search(r'\bcat\s+\S+\s*\|\s*(grep|awk|sed|head|tail|wc|sort|uniq|cut|tr)\b', stripped):
        findings.append(Finding(
            filepath, line_num, "warning", "W003",
            "Useless use of cat (piping cat to another command)",
            "Pass the file as an argument to the command directly"
        ))
    return findings


def check_unbraced_variable(filepath, line_num, line):
    """W004: Variable not in braces."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings

    # Remove quoted strings for analysis
    check_line = re.sub(r"'[^']*'", '', stripped)

    # Find $VAR that is not ${VAR} and not a special variable ($?, $!, etc.)
    for match in re.finditer(r'\$([A-Za-z_][A-Za-z_0-9]*)', check_line):
        # Check that it's NOT already braced
        pos = match.start()
        if pos + 1 < len(check_line) and check_line[pos + 1] == '{':
            continue
        var_name = match.group(1)
        findings.append(Finding(
            filepath, line_num, "warning", "W004",
            f"Variable '${var_name}' not in braces",
            f"Use '${{{var_name}}}' for clarity and safety"
        ))
        # Only report once per line
        break

    return findings


def check_legacy_test(filepath, line_num, line):
    """W005: Using test or [ instead of [[."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings
    # Match [ ... ] but not [[ ... ]]
    # Match standalone 'test' command
    if re.search(r'(?<!\[)\[\s+[^[]', stripped) or re.search(r'\btest\s+', stripped):
        # Make sure it's not [[ (check for single [ not preceded by [)
        if '[[' not in stripped:
            findings.append(Finding(
                filepath, line_num, "warning", "W005",
                "Using 'test' or '[' instead of '[['",
                "Use '[[' for conditional tests in bash (safer word splitting and globbing)"
            ))
    return findings


def check_long_lines(filepath, line_num, line):
    """I001: Long lines."""
    findings = []
    if len(line.rstrip('\n')) > 120:
        findings.append(Finding(
            filepath, line_num, "info", "I001",
            f"Line is {len(line.rstrip(chr(10)))} characters long (>120)",
            "Break long lines with backslash continuation or refactor"
        ))
    return findings


def check_todo_comments(filepath, line_num, line):
    """I002: TODO/FIXME/HACK comments."""
    findings = []
    if re.search(r'#.*\b(TODO|FIXME|HACK)\b', line):
        tag = re.search(r'#.*\b(TODO|FIXME|HACK)\b', line).group(1)
        findings.append(Finding(
            filepath, line_num, "info", "I002",
            f"{tag} comment found",
            f"Address or remove the {tag} comment"
        ))
    return findings


def check_uppercase_vars(filepath, line_num, line):
    """I003: Using uppercase variable names for non-env/non-constants."""
    findings = []
    stripped = line.strip()
    if stripped.startswith("#"):
        return findings
    # Match local variable assignments with uppercase names
    # local VARNAME=... or VARNAME=... (without export/readonly/declare)
    m = re.match(r'^(?:local\s+)([A-Z][A-Z_0-9]+)=', stripped)
    if m:
        var_name = m.group(1)
        findings.append(Finding(
            filepath, line_num, "info", "I003",
            f"Uppercase variable name '{var_name}' used (convention: lowercase for locals)",
            "Use lowercase for local variables; reserve UPPERCASE for exported/constant variables"
        ))
    return findings


def lint_file(filepath):
    """Lint a single file and return findings."""
    findings = []

    if not os.path.exists(filepath):
        return None, f"File not found: {filepath}"

    if not os.path.isfile(filepath):
        return None, f"Not a regular file: {filepath}"

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (IOError, OSError) as e:
        return None, f"Cannot read file: {filepath}: {e}"

    # Whole-file checks
    raw_lines = [l.rstrip('\n') for l in lines]
    findings.extend(check_shebang(filepath, raw_lines))
    findings.extend(check_error_handling(filepath, raw_lines))

    # Line-by-line checks
    for i, line in enumerate(lines, 1):
        findings.extend(check_unquoted_variable(filepath, i, line))
        findings.extend(check_eval(filepath, i, line))
        findings.extend(check_backticks(filepath, i, line))
        findings.extend(check_unsafe_temp(filepath, i, line))
        findings.extend(check_cd_no_check(filepath, i, line))
        findings.extend(check_useless_cat(filepath, i, line))
        findings.extend(check_unbraced_variable(filepath, i, line))
        findings.extend(check_legacy_test(filepath, i, line))
        findings.extend(check_long_lines(filepath, i, line))
        findings.extend(check_todo_comments(filepath, i, line))
        findings.extend(check_uppercase_vars(filepath, i, line))

    return findings, None


def format_text(all_findings, severity_filter):
    """Format findings as human-readable text."""
    output_lines = []
    total_errors = 0
    total_warnings = 0
    total_info = 0

    for filepath, findings in all_findings.items():
        for f in findings:
            if SEVERITY_LEVELS[f.severity] <= SEVERITY_LEVELS[severity_filter]:
                output_lines.append(f.to_text())
            # Always count for summary
        total_errors += sum(1 for f in findings if f.severity == "error")
        total_warnings += sum(1 for f in findings if f.severity == "warning")
        total_info += sum(1 for f in findings if f.severity == "info")

    if not output_lines:
        print("No issues found.")
    else:
        for line in output_lines:
            print(line)
        print()
        # Filter summary counts based on severity filter
        parts = []
        if SEVERITY_LEVELS["error"] <= SEVERITY_LEVELS[severity_filter]:
            parts.append(f"{total_errors} error{'s' if total_errors != 1 else ''}")
        if SEVERITY_LEVELS["warning"] <= SEVERITY_LEVELS[severity_filter]:
            parts.append(f"{total_warnings} warning{'s' if total_warnings != 1 else ''}")
        if SEVERITY_LEVELS["info"] <= SEVERITY_LEVELS[severity_filter]:
            parts.append(f"{total_info} info")
        print(f"Found {', '.join(parts)}")

    return total_errors


def format_json(all_findings, severity_filter):
    """Format findings as JSON."""
    result = {"files": [], "summary": {"errors": 0, "warnings": 0, "info": 0}}

    for filepath, findings in all_findings.items():
        filtered = [f for f in findings if SEVERITY_LEVELS[f.severity] <= SEVERITY_LEVELS[severity_filter]]
        file_entry = {
            "path": filepath,
            "findings": [f.to_dict() for f in filtered],
        }
        result["files"].append(file_entry)
        result["summary"]["errors"] += sum(1 for f in findings if f.severity == "error")
        result["summary"]["warnings"] += sum(1 for f in findings if f.severity == "warning")
        result["summary"]["info"] += sum(1 for f in findings if f.severity == "info")

    print(json.dumps(result, indent=2))
    return result["summary"]["errors"]


def main():
    parser = argparse.ArgumentParser(description="Shell script linter")
    parser.add_argument("files", nargs="*", help="Bash script files to lint")
    parser.add_argument("--format", dest="output_format", choices=["text", "json"],
                        default="text", help="Output format (default: text)")
    parser.add_argument("--severity", choices=["error", "warning", "info"],
                        default="info", help="Minimum severity to show (default: info)")

    args = parser.parse_args()

    if not args.files:
        parser.print_help()
        sys.exit(2)

    all_findings = {}
    file_error = False

    for filepath in args.files:
        findings, err = lint_file(filepath)
        if err:
            print(f"ERROR: {err}", file=sys.stderr)
            file_error = True
            continue
        all_findings[filepath] = findings

    if file_error and not all_findings:
        sys.exit(2)

    if args.output_format == "json":
        total_errors = format_json(all_findings, args.severity)
    else:
        total_errors = format_text(all_findings, args.severity)

    if file_error:
        sys.exit(2)
    elif total_errors > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
