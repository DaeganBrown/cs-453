from flask import Flask, jsonify
import os

app = Flask(__name__)

# TODO (Slide 17): read REDIS_HOST and REDIS_PORT from environment
#   variables instead of hardcoding them. Use os.environ.get(...).

# TODO (Slide 23): connect to Redis with retry logic (a short loop with
#   a few attempts and a short delay) so this app doesn't crash if Redis
#   isn't ready yet. Don't just assume the connection works, call
#   r.ping() and handle the failure case.


# TODO (Slide 21): add a POST route (e.g. "/data") that writes a value
#   to Redis. This is your write endpoint (Requirement 2).

# TODO (Slide 21): add a GET route (e.g. "/data") that reads that value
#   back from Redis. This is your read endpoint (Requirement 2).

# TODO (Slide 22): use jsonify(...) for every response, not a manually
#   built string or a raw Python dict. See Slide 22 for why this matters.


if __name__ == "__main__":
    # Do not change host="0.0.0.0" below. See Slide 19: if this is left
    # as Flask's default (127.0.0.1), your app only accepts connections
    # from inside its own container, and neither Compose's port mapping
    # nor the grading script will be able to reach it.
    app.run(host="0.0.0.0", port=5000)

