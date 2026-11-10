#!/bin/sh
# The TURN client protocol, unit-tested with a fake challenge. No database, no server
# process, no network.
set -eu
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    name=$1
    printf '%s\n' "turn protocol: $name"
    if ! cargo test -p sfu --lib "turn::tests::$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
        cat "$log"
        return 1
    fi
    cat "$log"
    grep -Fq "running 1 test" "$log"
    grep -Fq "test turn::tests::$name ... ok" "$log"
    if grep -Eq '(^|[[:space:]])skipped:' "$log"; then
        echo 'FAIL: a fixture skipped' >&2
        return 1
    fi
}
# Every test in crates/sfu/src/turn.rs's tests module, so the driver covers the whole
# protocol: the credentials challenge (401 and 438, encoded the way RFC 5389 §15.6 lays
# them out), the allocate with its four-byte REQUESTED-TRANSPORT, send-indication padding,
# retransmits and retry exhaustion, the refresh and permission/channel timers, the request
# queue, and the datagram hygiene (cookie, length, unguessable transaction ids, IPv6
# relayed addresses failing fast).
run challenges_exhaust_the_retries_and_fail_the_session
run allocate_runs_the_challenge_and_names_the_relayed_address
run send_wraps_as_an_indication_until_the_channel_is_bound
run the_allocation_retries_until_the_server_answers
run the_allocation_fails_after_its_retries
run the_allocation_refreshes_before_its_lifetime_runs_out
run a_short_lifetime_refreshes_at_half_instead_of_every_poll
run the_permissions_and_channels_refresh_on_their_own_timers
run a_permission_success_stamps_only_the_peer_it_was_for
run a_permission_queued_behind_a_refresh_still_goes_out
run a_permission_timeout_drops_the_request_and_keeps_the_session
run an_ipv6_relayed_address_fails_the_session_instead_of_retrying
run datagrams_without_the_magic_cookie_or_a_matching_length_are_dropped
run transaction_ids_carry_no_constant_bytes_and_repeat_never
printf '%s\n' 'PASS: the TURN client answers its challenge, allocates, sends, refreshes on its timers, queues behind the wire, and times out on schedule.'
