#!/bin/sh
# The real router and a fresh database per test, never a live community. API evidence only.
set -eu
: "${TEST_DATABASE_URL_MIGRATE:?set a disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    name=$1
    printf '%s\n' "passkey API integration: $name"
    if ! cargo test -p api --test passkey "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
        cat "$log"
        return 1
    fi
    cat "$log"
    # Cargo succeeds with no matching tests, and the shared fixture skips without DB URLs.
    # Neither is evidence. Require the named test to have actually completed successfully.
    grep -Fq "running 1 test" "$log"
    grep -Fq "test $name ... ok" "$log"
    grep -Fq 'test result: ok. 1 passed; 0 failed;' "$log"
    if grep -Eq '(^|[[:space:]])skipped:' "$log"; then
        echo 'FAIL: an integration fixture skipped' >&2
        return 1
    fi
}
run a_newer_session_does_not_make_an_old_one_recent
run an_old_session_cannot_change_how_the_account_signs_in
printf '%s\n' 'PASS: 2 passkey API integration tests; no native client proof.'
