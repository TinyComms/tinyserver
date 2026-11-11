#!/bin/sh
# Boots deploy/compose.yml, then lays compose.passkey.yml over it as step 9 of
# docs/auth-passkeys.md does, and checks the server comes back with the same end-to-end key.
# Real containers in a compose project of its own; never a live community. README.md here says
# what it proves.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
project=${E2E_PROJECT:-tinyserver-e2e-passkey-overlay}
# A range of its own, so a community on the same host keeps the default one.
subnet=${E2E_SUBNET:-172.31.253.0/24}
tunnel_ip=${E2E_TUNNEL_IP:-172.31.253.10}
key=/var/lib/tinyserver-keys/e2ee-server-key
# Git Bash on Windows would otherwise rewrite container paths.
MSYS_NO_PATHCONV=1
export MSYS_NO_PATHCONV

work=$(mktemp -d)
base="-f $repo/deploy/compose.yml -f $here/compose.lab.yml"
passkey="-f $repo/deploy/compose.yml -f $repo/deploy/compose.passkey.yml -f $here/compose.lab.yml"

say() { printf '%s\n' "$*"; }
random_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
# compose FILES ARGS...
compose() {
    files=$1
    shift
    # shellcheck disable=SC2086
    docker compose -p "$project" --env-file "$work/env" $files "$@"
}
cleanup() {
    compose "$base" down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
}
die() {
    say "FAIL: $*" >&2
    say '--- tinyserver, last lines ---' >&2
    compose "$base" logs --no-color --tail 30 tinyserver >&2 2>/dev/null || true
    exit 1
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir -m 700 "$work/secrets"
random_hex 32 >"$work/secrets/oidc_client_secret"
random_hex 32 >"$work/secrets/pocketid_api_key"
# No trailing newline: Pocket ID reads this one byte for byte.
printf %s "$(random_hex 32)" >"$work/secrets/pocketid_encryption_key"
chmod 444 "$work/secrets/"*
cat >"$work/env" <<EOF
POSTGRES_PASSWORD=$(random_hex 16)
APP_OWNER_PASSWORD=$(random_hex 16)
APP_RUNTIME_PASSWORD=$(random_hex 16)
TINYSERVER_MEDIA_HMAC_SECRET=$(random_hex 32)
TINYSERVER_PUBLIC_URL=https://chat.example.test
AUTH_PUBLIC_URL=https://auth.example.test
TUNNEL_TOKEN=unused
TINYSERVER_SECRETS_DIR=$work/secrets
TINYSERVER_INSIDE_SUBNET=$subnet
TINYSERVER_TUNNEL_IP=$tunnel_ip
EOF

# Leftovers of a run that was killed.
compose "$base" down --volumes --remove-orphans >/dev/null 2>&1 || true

health() {
    compose "$1" exec -T postgres wget -q -O - http://tinyserver:8080/health 2>/dev/null
}
# serving FILES WHAT: waits until /health answers. A server that exited fails at once.
serving() {
    tries=0
    while [ "$tries" -lt 90 ]; do
        if health "$1" | grep -q .; then
            say "ok   $2: /health answers"
            return 0
        fi
        state=$(compose "$1" ps --all --format '{{.State}}' tinyserver 2>/dev/null || true)
        case $state in
            exited | dead) die "$2: tinyserver stopped instead of serving" ;;
        esac
        tries=$((tries + 1))
        sleep 2
    done
    die "$2: /health did not answer in three minutes"
}
key_file() {
    compose "$1" exec -T tinyserver sha256sum "$key" | cut -d' ' -f1
}
key_row() {
    compose "$1" exec -T postgres psql -U postgres -d tinyserver -Atc \
        "select encode(signature_key, 'hex') from e2ee_server_key"
}

say '1. deploy/compose.yml, with Pocket ID'
if [ -n "${E2E_NO_BUILD:-}" ]; then
    compose "$base" up -d --no-build
else
    compose "$base" up -d --build
fi
serving "$base" 'with Pocket ID'
file_before=$(key_file "$base")
row_before=$(key_row "$base")
[ -n "$file_before" ] || die 'the first start wrote no key file'
[ -n "$row_before" ] || die 'the first start stored no public key'

say '2. compose.passkey.yml over it (docs/auth-passkeys.md, step 9)'
compose "$passkey" up -d --no-build
serving "$passkey" 'passkeys only'
compose "$passkey" logs --no-color tinyserver | grep -Fq 'sign-in ready: passkeys only' ||
    die 'the server did not start without a provider'
[ "$(compose "$passkey" exec -T tinyserver printenv TINYSERVER_E2EE_KEY_FILE)" = "$key" ] ||
    die 'TINYSERVER_E2EE_KEY_FILE is not what compose.yml set'
[ "$(key_file "$passkey")" = "$file_before" ] || die 'the key file changed'
[ "$(key_row "$passkey")" = "$row_before" ] || die 'the public key in the database changed'
say 'ok   passkeys only: the key file and the public key are the ones from step 1'

say '3. a restart with the overlay still on'
compose "$passkey" restart tinyserver
serving "$passkey" 'after a restart'
[ "$(key_file "$passkey")" = "$file_before" ] || die 'the key file changed over a restart'
say 'ok   after a restart: the same key file'

say 'PASS: the server starts under compose.passkey.yml and keeps its end-to-end key.'
