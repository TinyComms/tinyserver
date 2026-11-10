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
run the_allocation_retries_until_the_server_answers
run challenges_exhaust_the_retries_and_fail_the_session
run allocate_runs_the_challenge_and_names_the_relayed_address
printf '%s\n' 'PASS: the TURN client answers its challenge, retries, and exhausts a server that never accepts.'
