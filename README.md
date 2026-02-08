# shell-linter

Lint bash scripts for common mistakes, security issues, and style violations.

## Quick Start

```bash
python3 scripts/run.py myscript.sh
```

## Prerequisites

- Python 3.10+
- No external dependencies

## Usage

```bash
# Lint a script
python3 scripts/run.py script.sh

# Only show warnings and errors
python3 scripts/run.py --severity warning script.sh

# JSON output
python3 scripts/run.py --format json script.sh

# Multiple files
python3 scripts/run.py *.sh
```
