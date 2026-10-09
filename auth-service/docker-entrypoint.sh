#!/bin/sh
set -eu

secret_file=/app/data/jwt-secret

if [ -z "${AUTH_JWT_SECRET:-}" ]; then
    if [ ! -f "$secret_file" ]; then
        umask 077
        python -c "import secrets; print(secrets.token_urlsafe(48))" >"$secret_file"
    fi
    chmod 600 "$secret_file"
    AUTH_JWT_SECRET=$(cat "$secret_file")
    export AUTH_JWT_SECRET
fi

exec "$@"
