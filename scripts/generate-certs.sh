#!/bin/sh
# Generate the self-signed certificates Deep Vigilance needs to start.
#
# Run this from the repository root BEFORE the first `docker compose up`:
#
#     ./scripts/generate-certs.sh
#
# nginx mounts ./nginx/ssl read-only, so the certificates have to exist on the
# host first. Both paths can be overridden:
#
#     CERT_DIR=./nginx/ssl  INTERNAL_CERT_DIR=./certs  ./scripts/generate-certs.sh
#
# Self-signed certificates make browsers warn. That is expected for a local or
# internal deployment. For anything reachable from the internet, replace
# nginx/ssl/server.{crt,key} with a real certificate — see INSTALL.md.
set -e

# Default to paths relative to the repository root, so the script works when run
# from a checkout. Inside a container, pass the absolute paths instead.
REPO_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
CERT_DIR="${CERT_DIR:-$REPO_ROOT/nginx/ssl}"
INTERNAL_CERT_DIR="${INTERNAL_CERT_DIR:-$REPO_ROOT/certs}"

# Subject and SANs for the edge certificate. Override CERT_CN / CERT_SAN when
# serving a real hostname so the certificate matches the URL you browse to.
CERT_CN="${CERT_CN:-localhost}"
CERT_SAN="${CERT_SAN:-DNS:localhost,DNS:nginx,DNS:backend,IP:127.0.0.1}"
CERT_DAYS="${CERT_DAYS:-365}"
CERT_SUBJ="${CERT_SUBJ:-/O=Deep Vigilance/CN=$CERT_CN}"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ]; then
    echo "Generating edge certificate in $CERT_DIR (CN=$CERT_CN)..."

    openssl req -x509 -nodes -days "$CERT_DAYS" -newkey rsa:4096 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -subj "$CERT_SUBJ" \
        -addext "subjectAltName=$CERT_SAN" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth,clientAuth"

    chmod 600 "$CERT_DIR/server.key"
    chmod 644 "$CERT_DIR/server.crt"

    echo "Edge certificate generated."
else
    echo "Edge certificate already exists in $CERT_DIR, skipping."
fi

mkdir -p "$INTERNAL_CERT_DIR"

if [ ! -f "$INTERNAL_CERT_DIR/internal.crt" ] || [ ! -f "$INTERNAL_CERT_DIR/internal.key" ]; then
    echo "Generating internal service certificate in $INTERNAL_CERT_DIR..."

    openssl req -x509 -nodes -days "$CERT_DAYS" -newkey rsa:4096 \
        -keyout "$INTERNAL_CERT_DIR/internal.key" \
        -out "$INTERNAL_CERT_DIR/internal.crt" \
        -subj "/O=Deep Vigilance/OU=Internal/CN=appsec-internal" \
        -addext "subjectAltName=DNS:backend,DNS:redis,DNS:postgres,DNS:worker,IP:127.0.0.1" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth,clientAuth"

    chmod 600 "$INTERNAL_CERT_DIR/internal.key"
    chmod 644 "$INTERNAL_CERT_DIR/internal.crt"

    echo "Internal certificate generated."
else
    echo "Internal certificate already exists in $INTERNAL_CERT_DIR, skipping."
fi

echo "Certificate generation complete."
