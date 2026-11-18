#!/bin/sh
# Pin round trip, cap, permission mask and events, against the real API and database.
# This is component evidence, never native-client certification.
set -eu
: "${TEST_DATABASE_URL_MIGRATE:?set an owned disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    name=$1
    [ -n "$name" ] || { echo "FAIL: empty test filter" >&2; return 1; }
    printf '%s\n' "message pins API integration: $name"
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
run a_message_can_be_pinned_listed_and_unpinned_and_a_delete_takes_its_pin
run the_51st_pin_is_pin_limit_and_an_unpin_frees_a_slot
run pinning_follows_the_channel_override_mask
run pin_events_carry_ids_and_reach_only_the_conversations_audience
printf '%s\n' 'PASS: 4 message-pins API component tests.'
