#!/usr/bin/env bash
# Local disposable SQL verification. Every database writer follows --owned.
set -euo pipefail

fork_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
driver_root="$(cd "${fork_root}/../kavtov/kavtov-driver-go" && pwd -P)"
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/phase3810.XXXXXXXX")"
unset TEST_DSN KAVTOV_TEST_DSN DB_PORT KAVTOV_TESTDB_OWNED
cleanup() {
    local status=$?
    trap - EXIT
    if ! (cd "${driver_root}" && go run ./internal/testdb/cmd/setup --owned --down); then
        status=1
    fi
    rm -rf -- "${log_dir}"
    exit "${status}"
}
trap cleanup EXIT
export TEST_DSN="$(cd "${driver_root}" && go run ./internal/testdb/cmd/setup --owned)"
test -n "${TEST_DSN}"
export KAVTOV_TEST_DSN="${TEST_DSN}" KAVTOV_TESTDB_OWNED=1

# Reject zero discovery and skips, including a skipped SQL child subtest.
check_events() {
    python3 - "$@" <<'PY'
import json
import sys

events = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
requested = sys.argv[2:]
if any(e.get("Action") in ("skip", "fail") for e in events):
    raise SystemExit("SQL verification failed or skipped")
for name in requested:
    if not any(e.get("Test") == name and e.get("Action") == "run" for e in events):
        raise SystemExit(f"SQL test did not run: {name}")
    if not any(e.get("Test") == name and e.get("Action") == "pass" for e in events):
        raise SystemExit(f"SQL test did not pass: {name}")
if not requested:
    raise SystemExit("SQL selection must be nonempty")
print(f"verified {len(requested)} named SQL tests with no skips")
PY
}

sqlstore_tests=(TestRecoveryScanQueryFlat TestInlineRecoveryIterationGuard TestInlineRecoveryMergeKeepsExistingSkippedKeys)
sqlstore_pattern="$(IFS='|'; echo "${sqlstore_tests[*]}")"
(cd "${fork_root}" && go test -json ./store/sqlstore -run "^(${sqlstore_pattern})$" -count=1) | tee "${log_dir}/sqlstore.json"
check_events "${log_dir}/sqlstore.json" "${sqlstore_tests[@]}"
cipher_tests=(TestInlineDecryptEquivalence TestInlineDecryptIterationSafeRecovery)
cipher_pattern="$(IFS='|'; echo "${cipher_tests[*]}")"
(cd "${fork_root}" && go test -json . -run "^(${cipher_pattern})$" -count=1) | tee "${log_dir}/cipher.json"
check_events "${log_dir}/cipher.json" "${cipher_tests[@]}"

# Full component commands are added by the final verification plan. Driver
# Ensure() sees KAVTOV_TESTDB_OWNED=1 and revalidates this endpoint, with no
# candidateDSN fallback; this marker is inherited by scripts/run-tests.sh.
