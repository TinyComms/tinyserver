#!/bin/sh
# The SFU's keyframe-budget behavior, on loopback with headless str0m clients. No database.
set -eu
cd "$(dirname "$0")/../../.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
run() {
    target=$1
    name=$2
    printf '%s\n' "sfu integration: $target::$name"
    if ! cargo test -p sfu --test "$target" "$name" -- --exact --nocapture --test-threads=1 >"$log" 2>&1; then
        cat "$log"
        return 1
    fi
    cat "$log"
    # Cargo succeeds with no matching tests. Neither is evidence. Require the named test to
    # have actually completed successfully.
    grep -Fq "running 1 test" "$log"
    grep -Fq "test $name ... ok" "$log"
    grep -Fq 'test result: ok. 1 passed; 0 failed;' "$log"
    if grep -Eq '(^|[[:space:]])skipped:' "$log"; then
        echo 'FAIL: an integration fixture skipped' >&2
        return 1
    fi
}
run keyframe_budget a_keyframe_bigger_than_a_layers_bucket_still_reaches_the_viewer
printf '%s\n' 'PASS: 1 sfu integration test; the tile leaves Connecting.'
