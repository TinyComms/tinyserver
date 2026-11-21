#!/usr/bin/env bash
set -euo pipefail
cargo test -p api --test groups --test messages --test reports
