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
    printf '%s\n' "fresh community general API integration: $name"
    if ! cargo test -p api --test bootstrap_general "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
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
run a_new_community_starts_with_exactly_one_general_channel
run the_seeded_channel_follows_the_e2ee_text_setting
run the_seed_happens_with_no_device_enrolled_yet
run a_deleted_general_is_not_brought_back_by_the_next_owner
printf '%s\n' 'PASS: 4 fresh-community general API integration tests; no native client proof beyond the channel list released clients already draw.'
