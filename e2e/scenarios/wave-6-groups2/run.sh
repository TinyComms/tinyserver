#!/bin/sh
set -eu
cargo test -p api --test e2ee_text --test group_calls --test groups
