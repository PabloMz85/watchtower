#!/bin/sh
set -eu

# Compose provides the same external credential to both services. Prometheus
# reads a private runtime file, not a token embedded in its public config.
: "${WATCHTOWER_HTTP_API_TOKEN:?WATCHTOWER_HTTP_API_TOKEN must be set}"
umask 077
mkdir -p /tmp/watchtower-auth
printf '%s' "$WATCHTOWER_HTTP_API_TOKEN" > /tmp/watchtower-auth/token
unset WATCHTOWER_HTTP_API_TOKEN
exec /bin/prometheus "$@"
