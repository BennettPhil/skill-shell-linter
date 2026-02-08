---
name: shell-linter
description: Lint bash scripts for common mistakes, security issues, and style violations with actionable fix suggestions.
version: 0.1.0
license: Apache-2.0
---

# Shell Script Linter

## Purpose

Checks bash/shell scripts for common mistakes, security vulnerabilities, and style violations. Reports issues with file, line number, severity, and a fix suggestion. Catches unquoted variables, missing error handling, unsafe temp files, and POSIX compatibility issues.

## Instructions

1. Run `python3 scripts/run.py` with one or more shell script paths as arguments.
2. The tool reads each file and applies pattern-based checks.
3. Issues are reported to stdout, one per line, in the format: `file:line: [severity] message (fix: suggestion)`.
4. Exit code is 0 if no errors found, 1 if errors found, 2 for usage errors.

## Inputs

- **Positional arguments**: One or more paths to shell script files (.sh, .bash, or any file).
- **`--severity`** (optional): Minimum severity to report: `info`, `warning`, `error`. Default: `info`.
- **`--format`** (optional): Output format: `text` (default) or `json`.

## Outputs

- Issues printed to stdout, one per line.
- Summary line at the end: `N issues found (E errors, W warnings, I info)`.
- JSON format outputs an array of issue objects.

## Constraints

- Pattern-based analysis only (no AST parsing).
- May produce false positives for complex quoting scenarios.
- Does not execute the scripts being analyzed.
