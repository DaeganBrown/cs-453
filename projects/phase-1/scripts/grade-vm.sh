#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

ask_credentials
unset JWKS_URL
docker compose up --build -d
wait_for_api
python3 ../../provided/p2/grade_phase1.py --source-dir . --target localhost:5000
