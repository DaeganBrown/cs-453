#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

JWKS_URL=http://auth:9000/jwks.json docker compose --profile local up --build -d
wait_for_api
AUTH_URL=http://localhost:9000 CLIENT_ID=dev CLIENT_SECRET=dev-secret \
    python3 ../../provided/p2/grade_phase1.py --source-dir . --target localhost:5000
