from flask import Flask, jsonify, request
import os, time, redis
from werkzeug.exceptions import HTTPException
from auth import require_scope

app = Flask(__name__)

host = os.environ.get("REDIS_HOST", "localhost")
port = int(os.environ.get("REDIS_PORT", "6379"))
for _ in range(5):
    try:
        r = redis.Redis(host=host, port=port, decode_responses=True)
        r.ping()
        break
    except redis.ConnectionError:
        time.sleep(1)
else:
    raise RuntimeError("Redis unreachable")


#=============================================================================#
#= Helpers                                                                   =#
#=============================================================================#

def add_to_datastore(value):
    r.set("value", value)
    return value

def get_from_datastore():
    return r.get("value")
    
#=============================================================================#
#= Routes                                                                    =#
#=============================================================================#

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.post("/data")
@require_scope("data:write")
def write_data():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "value" not in body:
        return jsonify({"error": "invalid_request", "error_description": 'Body must be JSON with a "value" key.'}), 400
    value = add_to_datastore(body["value"])
    return jsonify({"value": value})

@app.get("/data")
@require_scope("data:read")
def read_data():
    value = get_from_datastore()
    return jsonify({"value": value})

@app.errorhandler(HTTPException)
def http_error(e):
    return jsonify({"error": e.name.lower().replace(" ", "_"), "error_description": e.description}), e.code

@app.errorhandler(Exception)
def server_error(e):
    return jsonify({"error": "server_error", "error_description": "Internal server error."}), 500

if __name__ == "__main__":
    # Do not change host="0.0.0.0" below. See Slide 19: if this is left
    # as Flask's default (127.0.0.1), your app only accepts connections
    # from inside its own container, and neither Compose's port mapping
    # nor the grading script will be able to reach it.
    app.run(host="0.0.0.0", port=5000)

