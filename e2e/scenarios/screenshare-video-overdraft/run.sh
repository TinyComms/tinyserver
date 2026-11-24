#!/bin/sh
# Verifies keyframe overdraft recovery and SFU keyframe-budget admission without a database.
set -eu
cd "$(dirname "$0")/../../.."
cargo test -p sfu --features headless --lib an_oversized_keyframe_followed_by_a_refilled_delta_stays_unbroken -- --exact
cargo test -p sfu --test keyframe_budget a_keyframe_bigger_than_a_layers_bucket_still_reaches_the_viewer -- --exact --test-threads=1
