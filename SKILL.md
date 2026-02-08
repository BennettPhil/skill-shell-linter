---
name: shell-linter
description: A shell script linter that checks bash scripts for common mistakes, security issues, and style violations with actionable fix suggestions.
version: 0.1.0
license: Apache-2.0
entry: scripts/run.sh
---

# shell-linter

A static analysis tool for bash scripts that catches common mistakes, security issues, and style violations before they cause problems in production.

## Features

- **Error detection**: Missing shebang, unquoted variables, eval usage, backtick substitution, missing error handling
- **Warning detection**: Unsafe temp files, unchecked cd, useless cat, unbraced variables, legacy test syntax
- **Info detection**: Long lines, TODO/FIXME comments, uppercase variable naming conventions
- **Multiple output formats**: Human-readable text and machine-parseable JSON
- **Severity filtering**: Show only errors, warnings, or info-level findings
- **Actionable fixes**: Every finding includes a concrete suggestion for how to fix it

## Usage

```bash
# Lint a single script
./scripts/run.sh myscript.sh

# Lint multiple scripts
./scripts/run.sh script1.sh script2.sh

# JSON output
./scripts/run.sh --format=json myscript.sh

# Only show errors
./scripts/run.sh --severity=error myscript.sh
```

## Exit Codes

- `0` - No errors found (warnings and info are non-fatal)
- `1` - One or more errors found
- `2` - File access error (file not found, not readable)
