#!/bin/sh
# Real API/DB tests for moderator message delete. Component evidence, never native-client
# certification. The suite drives, in order: a moderator deleting another member's message
# over the API, the tombstone frame reaching a member socket, a member's own delete still
# working, and a member's delete of another person's message being refused.
set -eu
: "${TEST_DATABASE_URL_MIGRATE:?set an owned disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    name=$1
    printf '%s\n' "moderator message delete API integration: $name"
    if ! cargo test --locked -p api --test messages "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
        cat "$log"
        return 1
    fi
    cat "$log"
    grep -Fq 'running 1 test' "$log"
    grep -Fq "test $name ..." "$log"
    grep -Fq 'test result: ok. 1 passed; 0 failed;' "$log"
    if grep -Eq '(^|[[:space:]])skipped:' "$log"; then
        echo 'FAIL: database fixture skipped' >&2
        return 1
    fi
}
run a_moderator_can_delete_another_members_message
run a_member_without_the_bit_cannot_delete_and_a_direct_stays_author_only
printf '%s\n' 'PASS: 2 moderator message delete API component tests; released-client proof remains pending.'
