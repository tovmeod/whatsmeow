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

events = [json.loads(line) for line in open(sys.argv[1]) if line.startswith("{")]
requested = sys.argv[2:]
allowed_skips = set()
skip_reasons = {}
if requested and requested[0] == "--allow-existing-prod-fixture":
    requested = requested[1:]
    allowed_skips.add(("go.mau.fi/whatsmeow/store", "TestFlatSessionProdFixtures"))
    skip_reasons[("go.mau.fi/whatsmeow/store", "TestFlatSessionProdFixtures")] = "production fixtures unavailable; no production access authorized"
elif requested and requested[0] == "--allow-existing-driver-contract":
    requested = requested[1:]
    allowed_skips.add(("github.com/kavtov/kavtov-driver-go/internal/driver", "TestSubscriptionCacheContract"))
    skip_reasons[("github.com/kavtov/kavtov-driver-go/internal/driver", "TestSubscriptionCacheContract")] = "requires Python-owned CONTRACT_TEST_PHONES fixture; outside sender-key scope"
skipped = {(e.get("Package"), e.get("Test")) for e in events if e.get("Action") == "skip" and e.get("Test")}
if any(e.get("Action") in ("fail", "build-fail") for e in events) or skipped - allowed_skips:
    raise SystemExit("SQL verification failed or skipped")
for name in requested:
    if not any(e.get("Test") == name and e.get("Action") == "run" for e in events):
        raise SystemExit(f"SQL test did not run: {name}")
    if not any(e.get("Test") == name and e.get("Action") == "pass" for e in events):
        raise SystemExit(f"SQL test did not pass: {name}")
ran = { (e.get("Package"), e.get("Test")) for e in events if e.get("Action") == "run" and e.get("Test") }
passed = { (e.get("Package"), e.get("Test")) for e in events if e.get("Action") == "pass" and e.get("Test") }
if not ran or not (ran - skipped).issubset(passed):
    raise SystemExit("zero test discovery or incomplete test events")
print(f"verified {len(requested)} required named tests; {len(passed)} test/subtest runs passed; required skips=0; unrelated existing skips={len(skipped)}")
for package, test in sorted(skipped):
    print(f"existing out-of-scope skip: {package}/{test}: {skip_reasons[(package, test)]}")
PY
}

sqlstore_tests=(TestRecoveryScanQueryFlat TestInlineRecoveryIterationGuard TestInlineRecoveryMergeKeepsExistingSkippedKeys TestInlineCipherOriginalUnreplayedIdle TestInlineCipherOriginalRecoveredByExistingRetry TestInlineCipherRetainedSkippedKey TestInlineCipherPermanentlyLostOriginal TestInlineCipherObservableWriteInvalidation TestSenderKeyLocalQueryCost TestCacheMemoryBudget)
sqlstore_pattern="$(IFS='|'; echo "${sqlstore_tests[*]}")"
(cd "${fork_root}" && go test -json ./store/sqlstore -run "^(${sqlstore_pattern})$" -count=1) | tee "${log_dir}/sqlstore.json"
check_events "${log_dir}/sqlstore.json" "${sqlstore_tests[@]}"
cipher_tests=(TestInlineDecryptEquivalence TestInlineDecryptIterationSafeRecovery)
cipher_pattern="$(IFS='|'; echo "${cipher_tests[*]}")"
(cd "${fork_root}" && go test -json . -run "^(${cipher_pattern})$" -count=1) | tee "${log_dir}/cipher.json"
check_events "${log_dir}/cipher.json" "${cipher_tests[@]}"

(cd "${fork_root}" && go test -race -json ./store/sqlstore -run 'Test(SenderKey|NoDonorCache|InlineRecovery|InlineCipher|SKPin|PutSenderKeyStructureRecovery)' -count=1) | tee "${log_dir}/race.json"
check_events "${log_dir}/race.json" TestInlineCipherPermanentlyLostOriginal TestInlineCipherOriginalUnreplayedIdle
(cd "${fork_root}" && go test ./store/sqlstore -run '^$' -bench '^BenchmarkSenderKeyFixedNegativeHits$' -benchmem -benchtime=100ms -count=1) | tee "${log_dir}/bench.txt"
grep -q '^BenchmarkSenderKeyFixedNegativeHits' "${log_dir}/bench.txt"
echo 'benchmem reports local allocation/loop wall time; CPU=unmeasured production-runtime=unmeasured'

(cd "${fork_root}" && go test -json -p 1 ./... -count=1) | tee "${log_dir}/fork-full.json"
check_events "${log_dir}/fork-full.json" --allow-existing-prod-fixture "${cipher_tests[@]}" "${sqlstore_tests[@]}"
(cd "${driver_root}" && go test -race -json -count=1 ./internal/driver/...) | tee "${log_dir}/driver-race.json"
check_events "${log_dir}/driver-race.json" --allow-existing-driver-contract
# Ensure() and teardown revalidate the exact owned endpoint; no ambient DSN fallback.
(cd "${driver_root}" && ./scripts/run-tests.sh) | tee "${log_dir}/driver-full.json"
check_events "${log_dir}/driver-full.json" --allow-existing-driver-contract
echo 'Phase 38.10 local verification passed; expected D-09 original loss is separate from later decrypt. DECRYPT-01 remains open; Phase 38.9 remains INCONCLUSIVE.'
