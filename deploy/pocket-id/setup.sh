#!/bin/sh
# Sets up Pocket ID for deploy/compose.yml. Run from deploy/, as the user who runs docker compose:
#
#   sh pocket-id/setup.sh [first-admin-username]
#
# 1. Makes the secrets in deploy/secrets that are not there yet:
#      oidc_client_secret       tinyserver's client secret at Pocket ID
#      pocketid_api_key         Pocket ID's static API key, an admin key; tinyserver and this
#                               script use it, nobody logs in with it
#      pocketid_encryption_key  encrypts Pocket ID's private data at rest
# 2. Starts Pocket ID and waits until it is healthy.
# 3. Makes the OIDC client "tinyserver" through Pocket ID's API, or brings it up to date:
#    confidential, PKCE, callback ${TINYSERVER_PUBLIC_URL}/v1/auth/callback, back-channel logout
#    to tinyserver inside, no consent screen. Registers oidc_client_secret on it unless it is
#    there already.
# 4. With a username: makes that admin unless they exist, and prints a one-time login link, good
#    for an hour, where they add their passkey. Run it again for a fresh link.
#
# Every step is skipped when already done, so it is safe to run again. Pass compose options in
# COMPOSE, such as COMPOSE="docker compose -p tinyserver --env-file ../../.env". Secrets never
# appear in a command line: the API key and request bodies reach curl on its standard input.
set -eu

compose=${COMPOSE:-docker compose}
dir=${TINYSERVER_SECRETS_DIR:-./secrets}
curl_image=curlimages/curl:8.17.0@sha256:935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40
admin=${1:-}
client_id=tinyserver
# Git Bash on Windows would otherwise rewrite container paths.
MSYS_NO_PATHCONV=1
export MSYS_NO_PATHCONV

say() { printf '%s\n' "$*"; }
die() { printf 'setup: %s\n' "$*" >&2; exit 1; }

# --- 1. Secrets -------------------------------------------------------------------------------

mkdir -p "$dir"
chmod 700 "$dir"

# make NAME COMMAND...: writes the command's output to $dir/NAME unless the file has something.
make_secret() {
  name=$1
  shift
  if [ -s "$dir/$name" ]; then
    say "$dir/$name exists; kept."
    return
  fi
  (umask 077 && "$@" > "$dir/$name")
  say "Wrote $dir/$name."
}
make_secret oidc_client_secret openssl rand -hex 32
make_secret pocketid_api_key openssl rand -hex 32
# No trailing newline: Pocket ID reads this one byte for byte.
make_secret pocketid_encryption_key sh -c 'printf %s "$(openssl rand -base64 32)"'
# The containers read these as their own users (Pocket ID 65532, tinyserver 10001) through
# compose secrets. The directory stays closed to everyone else on the host.
chmod 444 "$dir/oidc_client_secret" "$dir/pocketid_api_key" "$dir/pocketid_encryption_key"

# --- 2. Pocket ID -------------------------------------------------------------------------------

config=$($compose config) || die "docker compose config failed; check the environment file"
setting() {
  printf '%s\n' "$config" | sed -n "s/^ *$1: *//p" | head -n 1 | sed 's/^"\(.*\)"$/\1/'
}
public_url=$(setting TINYSERVER_PUBLIC_URL | sed 's#/*$##')
auth_url=$(setting APP_URL | sed 's#/*$##')
[ -n "$public_url" ] || die "TINYSERVER_PUBLIC_URL is not set"
[ -n "$auth_url" ] || die "AUTH_PUBLIC_URL is not set"

say "Starting Pocket ID..."
$compose up -d --wait pocket-id
cid=$($compose ps -q pocket-id)
[ -n "$cid" ] || die "Pocket ID is not running"

api_key=$(cat "$dir/pocketid_api_key")

# api METHOD PATH [JSON]: calls Pocket ID from inside its own network namespace. Prints the body,
# then the HTTP status on the last line.
api() {
  {
    printf 'header = "X-API-Key: %s"\n' "$api_key"
    printf 'header = "Accept: application/json"\n'
    if [ $# -ge 3 ]; then
      printf 'header = "Content-Type: application/json"\n'
      printf 'data = "%s"\n' "$(printf '%s' "$3" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    fi
  } | docker run --rm -i --network "container:$cid" "$curl_image" \
    -sS -X "$1" -w '\n%{http_code}' --config - "http://127.0.0.1:1411$2"
}
status_of() { printf '%s\n' "$1" | tail -n 1; }
body_of() { printf '%s\n' "$1" | sed '$d'; }

# --- 3. The tinyserver client -------------------------------------------------------------------

client_json=$(cat <<EOF
{"name":"tinyserver","callbackURLs":["$public_url/v1/auth/callback"],"logoutCallbackURLs":[],"backchannelLogoutURL":"http://tinyserver:8080/v1/auth/backchannel-logout","isPublic":false,"pkceEnabled":true,"requiresReauthentication":false,"requiresPushedAuthorizationRequests":false,"skipConsent":true,"isGroupRestricted":false,"credentials":{}}
EOF
)
answer=$(api GET "/api/oidc/clients/$client_id")
case $(status_of "$answer") in
  200)
    answer=$(api PUT "/api/oidc/clients/$client_id" "$client_json")
    [ "$(status_of "$answer")" = 200 ] || die "client update: $(body_of "$answer")"
    say "Client $client_id exists; brought up to date."
    ;;
  404)
    create=$(printf '%s' "$client_json" | sed "s/^{/{\"id\":\"$client_id\",/")
    answer=$(api POST /api/oidc/clients "$create")
    [ "$(status_of "$answer")" = 201 ] || die "client create: $(body_of "$answer")"
    say "Client $client_id made."
    ;;
  *)
    die "client lookup: HTTP $(status_of "$answer"): $(body_of "$answer")"
    ;;
esac

# Pocket ID keeps a hash and the first 4 characters of each secret. The marker holds the hash of
# the secret this script registered, so a rerun knows without guessing from the prefix.
secret=$(cat "$dir/oidc_client_secret")
fingerprint=$(printf '%s' "$secret" | openssl dgst -sha256 -r | cut -d ' ' -f 1)
marker="$dir/oidc_client_secret.registered"
if [ -s "$marker" ] && [ "$(cat "$marker")" = "$fingerprint" ]; then
  say "Client secret registered earlier; kept."
else
  prefix=$(printf '%s' "$secret" | cut -c 1-4)
  answer=$(api GET "/api/oidc/clients/$client_id/secrets")
  [ "$(status_of "$answer")" = 200 ] || die "secret list: $(body_of "$answer")"
  if body_of "$answer" | grep -q "\"prefix\":\"$prefix\""; then
    say "A client secret starting $prefix is registered; kept."
  else
    answer=$(api POST "/api/oidc/clients/$client_id/secrets" "{\"secret\":\"$secret\"}")
    [ "$(status_of "$answer")" = 201 ] || die "secret register: HTTP $(status_of "$answer")"
    say "Registered $dir/oidc_client_secret on client $client_id."
  fi
  (umask 077 && printf '%s\n' "$fingerprint" > "$marker")
fi

# --- 4. The first admin -------------------------------------------------------------------------

if [ -z "$admin" ]; then
  say
  say "Done. For a first admin and their login link: sh pocket-id/setup.sh <username>"
  exit 0
fi
case $admin in
  *[!A-Za-z0-9_.@-]*) die "a username is letters, digits, and _ . @ -" ;;
esac

# The user whose username is exactly $admin, from a search. Splitting on { leaves each user's own
# fields at the start of a line, id first.
find_user() {
  body_of "$1" | tr '{' '\n' | grep "\"username\":\"$admin\"" |
    sed -n 's/^"id":"\([^"]*\)".*/\1/p' | head -n 1
}
answer=$(api GET "/api/users?search=$admin")
[ "$(status_of "$answer")" = 200 ] || die "user search: $(body_of "$answer")"
user_id=$(find_user "$answer")
if [ -n "$user_id" ]; then
  say "Admin $admin exists ($user_id)."
else
  answer=$(api POST /api/users "{\"username\":\"$admin\",\"firstName\":\"$admin\",\"displayName\":\"$admin\",\"isAdmin\":true}")
  [ "$(status_of "$answer")" = 201 ] || die "admin create: $(body_of "$answer")"
  user_id=$(body_of "$answer" | sed -n 's/^{"id":"\([^"]*\)".*/\1/p')
  [ -n "$user_id" ] || die "admin create: no id in the answer"
  say "Admin $admin made ($user_id)."
fi

answer=$(api POST "/api/users/$user_id/one-time-access-token" '{"ttl":"1h"}')
[ "$(status_of "$answer")" = 201 ] || die "login link: HTTP $(status_of "$answer")"
token=$(body_of "$answer" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || die "login link: no token in the answer"
say
say "One-time login link for $admin, good for an hour. Open it and add a passkey:"
say "  $auth_url/lc/$token"
say
say "Their Pocket ID user id, the subject tinyserver sees, is $user_id."
