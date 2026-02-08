#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINT="${SCRIPT_DIR}/lint.py"
PASS=0
FAIL=0
TMPDIR_BASE="$(mktemp -d)"

trap 'rm -rf "${TMPDIR_BASE}"' EXIT

pass_test() {
    PASS=$((PASS + 1))
    echo "  PASS: $1"
}

fail_test() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1"
    echo "        $2"
}

echo "=== Gate 1: Smoke Tests ==="

# Create a script with obvious issues
cat > "${TMPDIR_BASE}/bad.sh" << 'TESTEOF'
echo hello
rm -rf $DIR
eval "$input"
result=`whoami`
cd /tmp
cat file.txt | grep foo
tmpfile=/tmp/myapp.tmp
TESTEOF

OUTPUT="$(python3 "${LINT}" "${TMPDIR_BASE}/bad.sh" 2>&1 || true)"

# Smoke 1: Should find unquoted variable
if echo "${OUTPUT}" | grep -qF -- "E002"; then
    pass_test "Detects unquoted variable (E002)"
else
    fail_test "Detects unquoted variable (E002)" "Got: ${OUTPUT}"
fi

# Smoke 2: Should find eval usage
if echo "${OUTPUT}" | grep -qF -- "E003"; then
    pass_test "Detects eval usage (E003)"
else
    fail_test "Detects eval usage (E003)" "Got: ${OUTPUT}"
fi

# Smoke 3: Should find backtick substitution
if echo "${OUTPUT}" | grep -qF -- "E004"; then
    pass_test "Detects backtick usage (E004)"
else
    fail_test "Detects backtick usage (E004)" "Got: ${OUTPUT}"
fi

# Smoke 4: Should find missing shebang
if echo "${OUTPUT}" | grep -qF -- "E001"; then
    pass_test "Detects missing shebang (E001)"
else
    fail_test "Detects missing shebang (E001)" "Got: ${OUTPUT}"
fi

# Smoke 5: Should find useless cat
if echo "${OUTPUT}" | grep -qF -- "W003"; then
    pass_test "Detects useless cat (W003)"
else
    fail_test "Detects useless cat (W003)" "Got: ${OUTPUT}"
fi

# Smoke 6: Should find unsafe temp
if echo "${OUTPUT}" | grep -qF -- "W001"; then
    pass_test "Detects unsafe temp (W001)"
else
    fail_test "Detects unsafe temp (W001)" "Got: ${OUTPUT}"
fi

# Smoke 7: Should find missing error handling
if echo "${OUTPUT}" | grep -qF -- "E005"; then
    pass_test "Detects missing error handling (E005)"
else
    fail_test "Detects missing error handling (E005)" "Got: ${OUTPUT}"
fi

# Smoke 8: Exit code should be 1 (errors found)
python3 "${LINT}" "${TMPDIR_BASE}/bad.sh" > /dev/null 2>&1 && BAD_EXIT=0 || BAD_EXIT=$?
if [[ "${BAD_EXIT}" -eq 1 ]]; then
    pass_test "Exit code is 1 when errors found"
else
    fail_test "Exit code is 1 when errors found" "Got exit code: ${BAD_EXIT}"
fi

echo ""
echo "=== Gate 2: Contract Tests ==="

# Contract 1: Empty file
touch "${TMPDIR_BASE}/empty.sh"
EMPTY_OUTPUT="$(python3 "${LINT}" "${TMPDIR_BASE}/empty.sh" 2>&1 || true)"
if echo "${EMPTY_OUTPUT}" | grep -qF -- "E001"; then
    pass_test "Empty file: reports missing shebang"
else
    fail_test "Empty file: reports missing shebang" "Got: ${EMPTY_OUTPUT}"
fi

# Contract 2: Non-existent file
python3 "${LINT}" "${TMPDIR_BASE}/nonexistent.sh" > /dev/null 2>&1 && NE_EXIT=0 || NE_EXIT=$?
if [[ "${NE_EXIT}" -eq 2 ]]; then
    pass_test "Non-existent file: exit code 2"
else
    fail_test "Non-existent file: exit code 2" "Got exit code: ${NE_EXIT}"
fi

# Contract 3: JSON output format
cat > "${TMPDIR_BASE}/json_test.sh" << 'TESTEOF'
echo hello
rm -rf $DIR
TESTEOF

JSON_OUTPUT="$(python3 "${LINT}" --format=json "${TMPDIR_BASE}/json_test.sh" 2>&1 || true)"
if echo "${JSON_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'files' in d; assert 'summary' in d" 2>/dev/null; then
    pass_test "JSON output: valid JSON with files and summary"
else
    fail_test "JSON output: valid JSON with files and summary" "Got: ${JSON_OUTPUT}"
fi

# Contract 4: JSON output has correct structure
JSON_HAS_FINDINGS="$(echo "${JSON_OUTPUT}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
f = d['files'][0]['findings']
assert len(f) > 0
item = f[0]
assert 'line' in item
assert 'severity' in item
assert 'rule_id' in item
assert 'message' in item
assert 'fix' in item
print('ok')
" 2>&1 || echo "fail")"
if [[ "${JSON_HAS_FINDINGS}" == "ok" ]]; then
    pass_test "JSON output: findings have required fields"
else
    fail_test "JSON output: findings have required fields" "Got: ${JSON_HAS_FINDINGS}"
fi

# Contract 5: Severity filter - error only
cat > "${TMPDIR_BASE}/severity_test.sh" << 'TESTEOF'
echo hello
rm -rf $DIR
cd /tmp
TESTEOF

SEV_OUTPUT="$(python3 "${LINT}" --severity=error "${TMPDIR_BASE}/severity_test.sh" 2>&1 || true)"
# Should show errors but NOT warnings
if echo "${SEV_OUTPUT}" | grep -qF -- "E002"; then
    pass_test "Severity filter: shows errors when --severity=error"
else
    fail_test "Severity filter: shows errors when --severity=error" "Got: ${SEV_OUTPUT}"
fi

# Should NOT show warning text in the output lines (excluding summary)
SEV_LINES="$(echo "${SEV_OUTPUT}" | grep -c "WARNING" || true)"
if [[ "${SEV_LINES}" -eq 0 ]]; then
    pass_test "Severity filter: hides warnings when --severity=error"
else
    fail_test "Severity filter: hides warnings when --severity=error" "Got ${SEV_LINES} WARNING lines"
fi

# Contract 6: No arguments shows help and exits 2
python3 "${LINT}" > /dev/null 2>&1 && NOARG_EXIT=0 || NOARG_EXIT=$?
if [[ "${NOARG_EXIT}" -eq 2 ]]; then
    pass_test "No arguments: exit code 2"
else
    fail_test "No arguments: exit code 2" "Got exit code: ${NOARG_EXIT}"
fi

echo ""
echo "=== Gate 3: Integration Tests ==="

# Integration 1: Clean script should pass with exit 0
cat > "${TMPDIR_BASE}/clean.sh" << 'TESTEOF'
#!/usr/bin/env bash
set -euo pipefail

readonly CONFIG_DIR="/etc/myapp"

main() {
    local tmpfile
    tmpfile="$(mktemp)"
    trap 'rm -f "${tmpfile}"' EXIT

    if cd "${CONFIG_DIR}"; then
        grep "pattern" "${tmpfile}" || true
        echo "Done"
    fi
}

main "$@"
TESTEOF

python3 "${LINT}" "${TMPDIR_BASE}/clean.sh" > /dev/null 2>&1 && CLEAN_EXIT=0 || CLEAN_EXIT=$?
if [[ "${CLEAN_EXIT}" -eq 0 ]]; then
    pass_test "Clean script: exit code 0 (no errors)"
else
    CLEAN_OUTPUT="$(python3 "${LINT}" "${TMPDIR_BASE}/clean.sh" 2>&1 || true)"
    fail_test "Clean script: exit code 0 (no errors)" "Got exit ${CLEAN_EXIT}. Output: ${CLEAN_OUTPUT}"
fi

# Integration 2: Script with all issue types
cat > "${TMPDIR_BASE}/all_issues.sh" << 'TESTEOF'
echo start
rm -rf $MYDIR
eval "$cmd"
name=`hostname`
cd /var/log
cat /var/log/syslog | grep error
tmpfile=/tmp/allissues.tmp
[ -f file ] && echo exists
TESTEOF
# Add a very long line
python3 -c "print('# ' + 'x' * 130)" >> "${TMPDIR_BASE}/all_issues.sh"
# Add a TODO comment
echo "# TODO: fix this later" >> "${TMPDIR_BASE}/all_issues.sh"
# Add uppercase local var
echo 'local MYVAR="hello"' >> "${TMPDIR_BASE}/all_issues.sh"

ALL_OUTPUT="$(python3 "${LINT}" "${TMPDIR_BASE}/all_issues.sh" 2>&1 || true)"

# Check all rule categories appear
ALL_OK=true
for rule_id in E001 E002 E003 E004 E005 W001 W002 W003 W005 I001 I002; do
    if echo "${ALL_OUTPUT}" | grep -qF -- "${rule_id}"; then
        : # ok
    else
        fail_test "All issues: ${rule_id} detected" "Not found in output"
        ALL_OK=false
    fi
done
if [[ "${ALL_OK}" == "true" ]]; then
    pass_test "All issue types detected (E001-E005, W001-W003, W005, I001, I002)"
fi

# Integration 3: Multiple files
cat > "${TMPDIR_BASE}/multi1.sh" << 'TESTEOF'
#!/usr/bin/env bash
set -euo pipefail
echo "clean file"
TESTEOF

cat > "${TMPDIR_BASE}/multi2.sh" << 'TESTEOF'
echo dirty
rm $x
TESTEOF

MULTI_OUTPUT="$(python3 "${LINT}" "${TMPDIR_BASE}/multi1.sh" "${TMPDIR_BASE}/multi2.sh" 2>&1 || true)"
python3 "${LINT}" "${TMPDIR_BASE}/multi1.sh" "${TMPDIR_BASE}/multi2.sh" > /dev/null 2>&1 && MULTI_EXIT=0 || MULTI_EXIT=$?

# Should have findings from multi2 but not multi1
if echo "${MULTI_OUTPUT}" | grep -qF -- "multi2.sh"; then
    pass_test "Multiple files: findings from bad file"
else
    fail_test "Multiple files: findings from bad file" "Got: ${MULTI_OUTPUT}"
fi

if [[ "${MULTI_EXIT}" -eq 1 ]]; then
    pass_test "Multiple files: exit code 1 (errors in any file)"
else
    fail_test "Multiple files: exit code 1 (errors in any file)" "Got exit code: ${MULTI_EXIT}"
fi

# Integration 4: cd with error handling should NOT trigger W002
cat > "${TMPDIR_BASE}/cd_safe.sh" << 'TESTEOF'
#!/usr/bin/env bash
set -euo pipefail
cd /tmp || exit 1
if cd /var; then
    echo "ok"
fi
cd /home && echo "ok"
TESTEOF

CD_OUTPUT="$(python3 "${LINT}" "${TMPDIR_BASE}/cd_safe.sh" 2>&1 || true)"
if echo "${CD_OUTPUT}" | grep -qF -- "W002"; then
    fail_test "Safe cd: no false positive W002" "Got: ${CD_OUTPUT}"
else
    pass_test "Safe cd: no false positive W002"
fi

# Integration 5: Variable in assignment should NOT trigger E002
cat > "${TMPDIR_BASE}/assign_safe.sh" << 'TESTEOF'
#!/usr/bin/env bash
set -euo pipefail
myvar=$HOME
other=${PATH}
TESTEOF

ASSIGN_OUTPUT="$(python3 "${LINT}" "${TMPDIR_BASE}/assign_safe.sh" 2>&1 || true)"
if echo "${ASSIGN_OUTPUT}" | grep -qF -- "E002"; then
    fail_test "Assignment: no false positive E002" "Got: ${ASSIGN_OUTPUT}"
else
    pass_test "Assignment: no false positive E002"
fi

echo ""
echo "================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "================================"

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
echo "All tests passed!"
exit 0
