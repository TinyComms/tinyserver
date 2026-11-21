#!/usr/bin/env bash
set -euo pipefail
cargo test -p api --test server --test blocks --test mentions --test search --test previews --test emoji --test threads
cargo test -p sfu --test video_logs
