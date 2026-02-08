# shell-linter Examples

## Example 1: Lint a script with issues

Given `bad.sh`:
```bash
rm -rf $DIR
eval "$user_input"
result=`whoami`
cd /some/dir
cat file.txt | grep pattern
tmpfile=/tmp/myapp.tmp
```

Running the linter:
```bash
$ ./scripts/run.sh bad.sh
bad.sh:1: [E002] ERROR: Unquoted variable expansion '$DIR' - Quote it: "$DIR"
bad.sh:2: [E003] ERROR: Use of 'eval' is a security risk - Refactor to avoid eval; use arrays for dynamic commands
bad.sh:3: [E004] ERROR: Backtick command substitution - Use $() instead: result=$(whoami)
bad.sh:4: [W002] WARNING: 'cd' without error check - Use 'cd /some/dir || exit 1' or wrap in if
bad.sh:5: [W003] WARNING: Useless use of cat - Use 'grep pattern file.txt' directly
bad.sh:6: [W001] WARNING: Unsafe temp file using hardcoded /tmp path - Use mktemp: tmpfile=$(mktemp)

Found 3 errors, 3 warnings, 0 info
```

## Example 2: JSON output

```bash
$ ./scripts/run.sh --format=json bad.sh
{
  "files": [
    {
      "path": "bad.sh",
      "findings": [
        {
          "line": 1,
          "severity": "error",
          "rule_id": "E002",
          "message": "Unquoted variable expansion '$DIR'",
          "fix": "Quote it: \"$DIR\""
        }
      ]
    }
  ],
  "summary": {
    "errors": 3,
    "warnings": 3,
    "info": 0
  }
}
```

## Example 3: Severity filtering

```bash
# Only show errors (exit 1 if any found)
$ ./scripts/run.sh --severity=error script.sh

# Show warnings and above
$ ./scripts/run.sh --severity=warning script.sh

# Show everything including info
$ ./scripts/run.sh --severity=info script.sh
```

## Example 4: Clean script (no findings)

Given `clean.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

main() {
    local tmpfile
    tmpfile="$(mktemp)"
    trap 'rm -f "${tmpfile}"' EXIT

    if cd "${SCRIPT_DIR}"; then
        grep "pattern" "${tmpfile}" || true
    fi
}

main "$@"
```

```bash
$ ./scripts/run.sh clean.sh
No issues found.
$ echo $?
0
```

## Example 5: Multiple files

```bash
$ ./scripts/run.sh deploy.sh build.sh test.sh
deploy.sh:3: [E002] ERROR: Unquoted variable expansion '$DEPLOY_DIR' - Quote it: "$DEPLOY_DIR"
build.sh: No issues found.
test.sh:15: [W003] WARNING: Useless use of cat - Use 'grep pattern file' directly

Found 1 error, 1 warning, 0 info across 3 files
```
