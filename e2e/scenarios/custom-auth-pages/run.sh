#!/bin/sh
# The real router and a fresh database per test, never a live community.
set -eu
: "${TEST_DATABASE_URL_MIGRATE:?set a disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
name=custom_auth_pages_serve_tinyserver_branding_and_recovery_actions
printf '%s\n' "passkey API integration: $name"
if ! cargo test -p api --test passkey "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
    cat "$log"
    exit 1
fi
cat "$log"
grep -Fq "running 1 test" "$log"
grep -Fq "test $name ... ok" "$log"
grep -Fq 'test result: ok. 1 passed; 0 failed;' "$log"
if grep -Eq '(^|[[:space:]])skipped:' "$log"; then
    echo 'FAIL: an integration fixture skipped' >&2
    exit 1
fi
printf '%s\n' 'PASS: custom auth pages branding, favicon, recovery controls, and CSP verified.'
