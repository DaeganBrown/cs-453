#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

export AUTH_URL=http://localhost:9000 CLIENT_ID=dev CLIENT_SECRET=dev-secret
JWKS_URL=http://auth:9000/jwks.json docker compose --profile local up --build -d
wait_for_api
clear

API=http://localhost:5000/data

echo "=== No token: expect 401"
curl -si "$API"
echo -e "\n"

echo "=== Read-only token on write: expect 403"
RO=$(python3 get_token.py --scope data:read)
curl -si -X POST -H "Authorization: Bearer $RO" -H "Content-Type: application/json" -d '{"value":"hello"}' "$API"
echo -e "\n"

echo "=== Full-scope token write: expect 200"
FULL=$(python3 get_token.py)
curl -si -X POST -H "Authorization: Bearer $FULL" -H "Content-Type: application/json" -d '{"value":"hello"}' "$API"
echo -e "\n"

echo "=== Full-scope token read: expect 200 with the written value"
curl -si -H "Authorization: Bearer $FULL" "$API"
echo
