from flask import Flask, jsonify, request
import os, time, redis

app = Flask(__name__)

host = os.environ.get("REDIS_HOST", "localhost")
port = int(os.environ.get("REDIS_PORT", "6379"))
for _ in range(5):
    try:
        r = redis.Redis(host=host, port=port)
        r.ping()
        break
    except redis.ConnectionError:
        time.sleep(2)
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

@app.route("/data", methods=["POST"])
def write_data():
    value = add_to_datastore(request.get_json()["value"])
    return jsonify({"value": value})

@app.route("/data", methods=["GET"])
def read_data():
    value = get_from_datastore()
    return jsonify({"value": value})

if __name__ == "__main__":
    # Do not change host="0.0.0.0" below. See Slide 19: if this is left
    # as Flask's default (127.0.0.1), your app only accepts connections
    # from inside its own container, and neither Compose's port mapping
    # nor the grading script will be able to reach it.
    app.run(host="0.0.0.0", port=5000)

