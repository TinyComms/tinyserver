#!/bin/sh
# Actual HTTP integration against fresh databases, never a live community.
set -eu
: "${TEST_DATABASE_URL_MIGRATE:?set a disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    target=$1
    name=$2
    printf '%s\n' "server integration: $target::$name"
    if ! cargo test -p api --test "$target" "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
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
run messages a_channel_body_says_what_the_caller_may_do_there
printf '%s\n' 'PASS: 1 server integration test; released-client proof remains pending.'
