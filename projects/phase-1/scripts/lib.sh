cd "$(dirname "$0")/.."
ENV_FILE=${ENV_FILE:-$HOME/.cs453.env}
[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE"; set +a; }
trap 'docker compose --profile local down >/dev/null 2>&1' EXIT

ask_credentials() {
    export AUTH_URL=${AUTH_URL:-http://10.168.26.24:9000}
    [[ -n "${CLIENT_ID:-}" ]] || read -rp "Client ID: " CLIENT_ID
    [[ -n "${CLIENT_SECRET:-}" ]] || { read -rsp "Client secret: " CLIENT_SECRET; echo; }
    export CLIENT_ID CLIENT_SECRET
}

wait_for_api() {
    for _ in {1..30}; do
        curl -sf http://localhost:5000/health >/dev/null && return
        sleep 1
    done
    echo "API did not become ready" >&2
    docker compose logs api >&2
    exit 1
}
