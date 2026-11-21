#!/bin/sh
# Deploy-gate scenario: drive the last released tinyclient's headless video probe against this
# branch's disposable server fixture and assert both the client proof marker and the server's
# info-level video publish/slot logs. Never uses real sessions or a community database.
set -eu

PROOF_MARKER="${CLIENT_PROOF_MARKER:-video-received-proof: room share+camera painted; direct share+camera painted; counters advance; cleared on stop}"

check_server_log() {
    log_path=$1
    if [ ! -f "$log_path" ]; then
        echo "FAIL: server log does not exist: $log_path" >&2
        return 1
    fi
    awk '
        function has_kv(line, key, val) {
            return (line ~ (key "=" val "([[:space:]]|$)")) || (line ~ (key "=\"" val "\"([[:space:]]|$)"))
        }
        /video publish/ {
            if (has_kv($0, "source", "share") && has_kv($0, "on", "true")) {
                share_pub = 1
            }
            if (has_kv($0, "source", "camera") && has_kv($0, "on", "true")) {
                cam_pub = 1
            }
        }
        /video slot/ && !/video slot empty/ {
            if (share_pub && has_kv($0, "layer", "share") && !has_kv($0, "from", "none")) {
                share_slot = 1
            }
            if (cam_pub && (has_kv($0, "layer", "l") || has_kv($0, "layer", "h")) && !has_kv($0, "from", "none")) {
                cam_slot = 1
            }
        }
        END {
            failed = 0
            if (!share_pub) {
                print "FAIL: server log missing '\''video publish'\'' with source=share on=true" > "/dev/stderr"
                failed = 1
            } else if (!share_slot) {
                print "FAIL: server log missing '\''video slot'\'' with layer=share after share publish (viewer slot never named the share)" > "/dev/stderr"
                failed = 1
            }
            if (!cam_pub) {
                print "FAIL: server log missing '\''video publish'\'' with source=camera on=true" > "/dev/stderr"
                failed = 1
            } else if (!cam_slot) {
                print "FAIL: server log missing '\''video slot'\'' with layer=l or layer=h after camera publish (viewer slot never named the camera)" > "/dev/stderr"
                failed = 1
            }
            exit failed
        }
    ' "$log_path"
}

if [ "${1:-}" = "--check-log" ]; then
    [ $# -eq 2 ] || { echo "usage: $0 --check-log <server-log>" >&2; exit 2; }
    check_server_log "$2"
    exit 0
fi

: "${TEST_DATABASE_URL_MIGRATE:?set a disposable Postgres owner URL with CREATEDB}"
: "${TEST_DATABASE_URL:?set the matching disposable Postgres runtime URL}"

repo_root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$repo_root"

python_bin="${PYTHON:-}"
if [ -z "$python_bin" ]; then
    if command -v python3 >/dev/null 2>&1; then
        python_bin=python3
    elif command -v python >/dev/null 2>&1; then
        python_bin=python
    else
        echo "FAIL: python3 or python is required to run tinyclient's tiny-video-received driver" >&2
        exit 1
    fi
fi

umask 077
work=$(mktemp -d)
fixture="$work/fixture.json"
server_log="$work/server.log"
client_log="$work/client.log"
fixture_pid=""

cleanup() {
    if [ -n "$fixture_pid" ] && kill -0 "$fixture_pid" 2>/dev/null; then
        kill -INT "$fixture_pid" 2>/dev/null || true
        i=0
        while [ "$i" -lt 20 ] && kill -0 "$fixture_pid" 2>/dev/null; do
            sleep 0.25
            i=$((i + 1))
        done
        if kill -0 "$fixture_pid" 2>/dev/null; then
            kill -TERM "$fixture_pid" 2>/dev/null || true
            sleep 0.5
        fi
        if kill -0 "$fixture_pid" 2>/dev/null; then
            kill -KILL "$fixture_pid" 2>/dev/null || true
        fi
        wait "$fixture_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

# Resolve the released tinyclient checkout (or an explicit branch/checkout while the probe is
# pending release, as allowed by docs/quality-gate.md).
if [ -n "${TINYCLIENT_DIR:-}" ]; then
    client_dir="$TINYCLIENT_DIR"
    [ -d "$client_dir" ] || { echo "FAIL: TINYCLIENT_DIR does not exist: $client_dir" >&2; exit 1; }
    client_desc="$client_dir"
else
    client_repo="${TINYCLIENT_REPO:-https://github.com/TinyComms/tinyclient.git}"
    client_ref="${TINYCLIENT_REF:-}"
    if [ -z "$client_ref" ]; then
        client_ref=$(git ls-remote --tags --refs "$client_repo" 'refs/tags/v*' \
            | awk '{ sub("refs/tags/", "", $2); print $2 }' \
            | sort -V \
            | tail -n 1)
        if [ -z "$client_ref" ]; then
            echo "FAIL: could not determine latest released tinyclient tag from $client_repo" >&2
            exit 1
        fi
    fi
    client_dir="$work/tinyclient"
    printf '%s\n' "video-received: checking out tinyclient $client_ref from $client_repo"
    git clone --depth 1 --branch "$client_ref" "$client_repo" "$client_dir" >/dev/null 2>&1 || {
        git init -q "$client_dir"
        git -C "$client_dir" fetch --depth 1 "$client_repo" "$client_ref"
        git -C "$client_dir" checkout -q FETCH_HEAD
    }
    client_desc="$client_repo@$client_ref"
fi

driver="$client_dir/e2e/scenarios/tiny-video-received/drive.py"
if [ ! -f "$driver" ]; then
    echo "FAIL: $driver not found in $client_desc" >&2
    echo "Hint: until a released tinyclient tag includes tiny-video-received (TinyComms/tinyclient#274)," >&2
    echo "      set TINYCLIENT_REF=<branch> or TINYCLIENT_DIR=<checkout> carrying that driver." >&2
    exit 1
fi

printf '%s\n' "video-received: starting disposable server fixture from $repo_root"
DIRECT_CALL_FIXTURE_FILE="$fixture" \
DIRECT_CALL_FIXTURE_SECONDS="${DIRECT_CALL_FIXTURE_SECONDS:-600}" \
cargo test -p api --test direct_fixture direct_calls_fixture_for_client -- --ignored --exact --nocapture \
    >"$server_log" 2>&1 &
fixture_pid=$!

wait_limit="${FIXTURE_WAIT_SECONDS:-180}"
waited=0
while [ "$waited" -lt "$wait_limit" ]; do
    if [ -s "$fixture" ] && grep -Fq '"room_id"' "$fixture" && grep -Fq '"base_url"' "$fixture"; then
        break
    fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then
        echo "FAIL: disposable server fixture exited before becoming ready" >&2
        cat "$server_log" >&2
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
done

if [ ! -s "$fixture" ] || ! grep -Fq '"room_id"' "$fixture"; then
    echo "FAIL: disposable server fixture did not write fixture JSON with room_id within ${wait_limit}s" >&2
    cat "$server_log" >&2
    exit 1
fi

if grep -Eq '(^|[[:space:]])skipped:' "$server_log"; then
    echo "FAIL: disposable server fixture skipped" >&2
    cat "$server_log" >&2
    exit 1
fi

printf '%s\n' "video-received: running client driver $driver ($client_desc)"
client_status=0
TINY_DIRECT_CALL_FIXTURE="$fixture" "$python_bin" "$driver" >"$client_log" 2>&1 || client_status=$?
cat "$client_log"

if [ "$client_status" -ne 0 ]; then
    echo "FAIL: client driver exited with status $client_status" >&2
    echo "--- server video logs ---" >&2
    grep -E 'video publish|video slot|share refused' "$server_log" >&2 || true
    exit 1
fi

if ! grep -Fq "$PROOF_MARKER" "$client_log"; then
    echo "FAIL: client driver output missing proof marker: $PROOF_MARKER" >&2
    exit 1
fi

if ! check_server_log "$server_log"; then
    echo "--- server video logs ---" >&2
    grep -E 'video publish|video slot|share refused' "$server_log" >&2 || true
    exit 1
fi

printf '%s\n' "PASS: video-received ($client_desc; client proof marker + server share/camera publish and slot logs verified)."
