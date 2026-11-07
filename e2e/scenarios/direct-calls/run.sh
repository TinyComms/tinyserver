#!/bin/sh
# Actual HTTP/WebSocket/SFU integration against fresh databases, never a live community.
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
run live a_direct_call_rings_the_pair_and_a_third_person_hears_nothing
run live a_direct_call_is_replayed_to_the_pair_only
run live a_restart_mid_ring_writes_no_direct_call
run live an_encrypted_direct_call_needs_no_text_device
run live leaving_an_accepted_direct_before_seating_keeps_the_other_room
run media a_direct_call_carries_voice_one_picture_and_ends_for_both
run media a_direct_blip_keeps_the_media_and_is_not_a_voice_channel
run e2ee a_direct_call_seals_under_its_media_room_and_need_not
printf '%s\n' 'PASS: 8 server integration tests; native client/GUI proof remains pending.'
