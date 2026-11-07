#!/bin/sh
# Real API/DB relay tests. This is component evidence, never native-client certification.
set -eu
: "${TEST_DATABASE_URL_MIGRATE:?set an owned disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    name=$1
    printf '%s\n' "device-link API integration: $name"
    if ! cargo test --locked -p api --test e2ee_link "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
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
run capabilities_advertise_device_links
run two_sessions_of_one_person_relay_messages
run someone_else_cannot_touch_a_link
run links_and_messages_are_capped
run link_creation_is_rate_limited
run an_expired_link_is_gone_and_its_archive_an_hour_later
run the_sweep_deletes_archive_files_no_row_names
run the_archive_round_trips_with_ranges_and_is_deleted_with_the_link
run the_archive_is_capped_and_a_bad_upload_leaves_nothing
run a_read_waits_for_the_next_message
printf '%s\n' 'PASS: 10 device-link API component tests; native-client/history proof and merge hold remain pending.'
