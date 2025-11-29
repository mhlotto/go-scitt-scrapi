#!/usr/bin/env bash
set -euo pipefail

# Quick demo-only certificate generator for HTTPS and mTLS.
# Generates a CA, server cert/key, and client cert/key under ./certs.
# Do NOT use in production.

OUT_DIR=${1:-certs}
mkdir -p "$OUT_DIR"

CA_KEY="$OUT_DIR/ca.key.pem"
CA_CRT="$OUT_DIR/ca.crt.pem"
SERVER_KEY="$OUT_DIR/server.key.pem"
SERVER_CSR="$OUT_DIR/server.csr.pem"
SERVER_CRT="$OUT_DIR/server.crt.pem"
CLIENT_KEY="$OUT_DIR/client.key.pem"
CLIENT_CSR="$OUT_DIR/client.csr.pem"
CLIENT_CRT="$OUT_DIR/client.crt.pem"

echo "Generating demo CA..."
openssl genrsa -out "$CA_KEY" 4096 >/dev/null
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 365 \
  -subj "/CN=Demo CA" -out "$CA_CRT" >/dev/null

echo "Generating server key/cert..."
openssl genrsa -out "$SERVER_KEY" 2048 >/dev/null
openssl req -new -key "$SERVER_KEY" -subj "/CN=localhost" -out "$SERVER_CSR" >/dev/null
cat >"$OUT_DIR/server.ext" <<EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CRT" -days 365 -sha256 -extfile "$OUT_DIR/server.ext" >/dev/null

echo "Generating client key/cert..."
openssl genrsa -out "$CLIENT_KEY" 2048 >/dev/null
openssl req -new -key "$CLIENT_KEY" -subj "/CN=demo-client" -out "$CLIENT_CSR" >/dev/null
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CRT" -days 365 -sha256 >/dev/null

echo "Done. Files:"
ls -1 "$OUT_DIR"

echo
echo "Server HTTPS + mTLS example:"
echo "  go run ./cmd/scrapi-demo-server -addr :8443 -auth-token secret \\\\"
echo "    -tls-cert $SERVER_CRT -tls-key $SERVER_KEY -tls-client-ca $CA_CRT"
echo
echo "Client example:"
echo "  go run ./cmd/scrapi-demo-client -addr https://localhost:8443 -token secret \\\\"
echo "    -tls-ca $CA_CRT -tls-cert $CLIENT_CRT -tls-key $CLIENT_KEY -sbom fixtures/sbom/sample-cyclonedx.json"
