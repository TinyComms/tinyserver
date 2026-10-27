#!/bin/sh
# Makes the two secrets deploy/compose.yml reads, in deploy/secrets:
#   oidc_client_secret  shared by Tinyauth and tinyserver
#   tinyauth_users      one line per person: username:bcrypt-hash:totp-secret
# Run from deploy/, as the user who runs docker compose. Nothing here is committed.
set -eu

image=ghcr.io/tinyauthapp/tinyauth:v5.2.0-distroless@sha256:aff752a57511f9346109b4d427c132db71dfa480138698e1f42feaf335f7cda9
dir=${TINYSERVER_SECRETS_DIR:-./secrets}

mkdir -p "$dir"
chmod 700 "$dir"

if [ ! -s "$dir/oidc_client_secret" ]; then
  (umask 077 && openssl rand -hex 32 > "$dir/oidc_client_secret")
  echo "Wrote $dir/oidc_client_secret."
else
  echo "$dir/oidc_client_secret exists; kept."
fi

echo
echo "Step 1 of 2: choose a username and password. Copy the username:hash line it prints."
docker run --rm -it "$image" user create --interactive
echo
echo "Step 2 of 2: paste that username:hash line to add TOTP. Scan the code with an"
echo "authenticator app, then copy the final username:hash:secret line."
docker run --rm -it "$image" totp generate --interactive
echo
printf 'Paste the final username:hash:secret line here: '
read -r line
case "$line" in
  *:*:*) ;;
  *)
    echo "That is not username:hash:secret. Nothing written." >&2
    exit 1
    ;;
esac
if [ -f "$dir/tinyauth_users" ]; then
  chmod 600 "$dir/tinyauth_users"
fi
(umask 077 && printf '%s\n' "$line" >> "$dir/tinyauth_users")
echo "Added to $dir/tinyauth_users."

# The containers run as other users (Tinyauth 65532, tinyserver 10001) and read the files
# through compose secrets. The directory stays closed to everyone else on the host.
chmod 444 "$dir/oidc_client_secret" "$dir/tinyauth_users"
