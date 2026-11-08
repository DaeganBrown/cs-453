"""
CS453 Phase 1 authorization server.

Implements just enough of OAuth 2.0 for the course project:

  POST /token        client credentials grant (RFC 6749 section 4.4)
  GET  /jwks.json    public signing keys (JWKS, RFC 7517)
  GET  /.well-known/oauth-authorization-server   discovery metadata (RFC 8414)
  POST /test-token   deliberately BAD tokens, so students can test rejection
  GET  /health

Access tokens are RS256 JWTs. The same code runs on the instructor's grader
VM and, as the "local" Compose service, inside each student's stack. The two
instances have different signing keys, which is why students fetch keys from
JWKS_URL instead of bundling them.

Configuration (environment variables):

  ISSUER           iss claim            (default cs453-auth)
  AUDIENCE         default aud claim    (default cs453-api); a client record
                   may override it, which is how per-student audiences work
  TOKEN_TTL        seconds              (default 1200, i.e. 20 minutes)
  CLIENTS_FILE     client registry      (default /data/clients.json)
  KEYS_DIR         signing key folder   (default /data/keys)
  ALLOW_DEV_CLIENT 1 = if CLIENTS_FILE is missing, accept dev / dev-secret
"""

import base64
import hashlib
import hmac
import json
import os
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

ISSUER = os.environ.get("ISSUER", "cs453-auth")
AUDIENCE = os.environ.get("AUDIENCE", "cs453-api")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "1200"))
CLIENTS_FILE = os.environ.get("CLIENTS_FILE", "/data/clients.json")
KEYS_DIR = os.environ.get("KEYS_DIR", "/data/keys")
ALLOW_DEV_CLIENT = os.environ.get("ALLOW_DEV_CLIENT") == "1"

ALL_SCOPES = ["data:read", "data:write"]

app = Flask(__name__)


# ---------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_int(n):
    return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def public_der(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def kid_for(private_key):
    return hashlib.sha256(public_der(private_key)).hexdigest()[:16]


def new_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def load_keys():
    """Load every *.pem in KEYS_DIR, newest first. Create one if none exist.
    The newest key signs. All keys are published, so an old key can be kept
    for a while after a rotation (drop a new .pem in the folder, restart)."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    paths = [os.path.join(KEYS_DIR, f) for f in os.listdir(KEYS_DIR) if f.endswith(".pem")]
    if not paths:
        key = new_private_key()
        path = os.path.join(KEYS_DIR, f"{kid_for(key)}.pem")
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        os.chmod(path, 0o600)
        paths = [path]
    paths.sort(key=os.path.getmtime, reverse=True)
    keys = []
    for p in paths:
        with open(p, "rb") as f:
            keys.append(serialization.load_pem_private_key(f.read(), password=None))
    return keys


KEYS = load_keys()
SIGNING_KEY = KEYS[0]
SIGNING_KID = kid_for(SIGNING_KEY)
SIGNING_PEM = SIGNING_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
# Never published anywhere. Used only to mint tokens that must be rejected.
ROGUE_KEY = new_private_key()
ROGUE_PEM = ROGUE_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)


def jwks():
    out = []
    for k in KEYS:
        nums = k.public_key().public_numbers()
        out.append({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid_for(k),
            "n": b64url_int(nums.n), "e": b64url_int(nums.e),
        })
    return {"keys": out}


# ---------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------

def sha256_hex(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def load_clients():
    if os.path.exists(CLIENTS_FILE):
        with open(CLIENTS_FILE, "r") as f:
            return json.load(f)["clients"]
    if ALLOW_DEV_CLIENT:
        return {"dev": {"secret_sha256": sha256_hex("dev-secret"),
                        "scopes": ALL_SCOPES, "name": "local development"}}
    raise SystemExit(f"No client registry at {CLIENTS_FILE}. "
                     "Run make_clients.py, or set ALLOW_DEV_CLIENT=1 for local use.")


CLIENTS = load_clients()


def authenticate_client():
    """Return (client_id, record) or (None, None). Accepts HTTP Basic or
    client_id / client_secret in the form body."""
    cid = secret = None
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            cid, _, secret = decoded.partition(":")
        except Exception:
            return None, None
    else:
        data = request.get_json(silent=True) if request.is_json else request.form
        data = data or {}
        cid, secret = data.get("client_id"), data.get("client_secret")
    if not cid or not secret:
        return None, None
    rec = CLIENTS.get(cid)
    # Always hash and compare, even for unknown ids, to keep timing uniform.
    expected = rec["secret_sha256"] if rec else sha256_hex("x")
    ok = hmac.compare_digest(sha256_hex(secret), expected)
    return (cid, rec) if (rec and ok) else (None, None)


def form_value(name, default=None):
    data = request.get_json(silent=True) if request.is_json else request.form
    return (data or {}).get(name, default)


def oauth_error(error, description, status=400, extra_headers=None):
    resp = jsonify({"error": error, "error_description": description})
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    for k, v in (extra_headers or {}).items():
        resp.headers[k] = v
    return resp


def resolve_scope(rec):
    """Requested scope must be a subset of what the client is allowed."""
    allowed = rec.get("scopes", ALL_SCOPES)
    requested = (form_value("scope") or "").split()
    if not requested:
        return list(allowed), None
    bad = [s for s in requested if s not in allowed]
    if bad:
        return None, f"scope not allowed for this client: {' '.join(bad)}"
    return requested, None


# ---------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------

def base_claims(cid, rec, scopes, now=None):
    now = int(now if now is not None else time.time())
    return {
        "iss": ISSUER,
        "sub": cid,
        "aud": rec.get("audience", AUDIENCE),
        "iat": now,
        "exp": now + TOKEN_TTL,
        "jti": str(uuid.uuid4()),
        "client_id": cid,
        "scope": " ".join(scopes),
    }


def sign(claims, pem=None, kid=None):
    return jwt.encode(claims, pem or SIGNING_PEM, algorithm="RS256",
                      headers={"kid": kid or SIGNING_KID})


def token_response(token, scopes, **extra):
    body = {"access_token": token, "token_type": "Bearer",
            "expires_in": TOKEN_TTL, "scope": " ".join(scopes)}
    body.update(extra)
    resp = jsonify(body)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


# Each kind: description of what the student's API must do with it.
BAD_KINDS = {
    "expired": "Valid in every way except it expired an hour ago. Expect 401 invalid_token.",
    "wrong-audience": "Issued for a different audience. Expect 401 invalid_token.",
    "wrong-issuer": "Issued by a different issuer. Expect 401 invalid_token.",
    "rogue-key": "Claims are correct and the kid is real, but the signature was made with a key that is not in the JWKS. Expect 401 invalid_token.",
    "unknown-kid": "Signed by a key that is not in the JWKS and carrying a kid your API has never seen. Your API may refetch the JWKS once, then must answer 401 invalid_token.",
    "alg-none": "An unsigned token whose header claims alg none. Expect 401 invalid_token.",
    "hs256-confusion": "Header claims HS256 and the signature is an HMAC keyed with the server's public key. Expect 401 invalid_token.",
    "no-scope": "Completely valid but carries no scopes. Expect 403 insufficient_scope on /data.",
}


def make_bad_token(kind, cid, rec, scopes):
    now = int(time.time())
    c = base_claims(cid, rec, scopes, now)
    if kind == "expired":
        c["iat"], c["exp"] = now - 7200, now - 3600
        return sign(c)
    if kind == "wrong-audience":
        c["aud"] = "some-other-api"
        return sign(c)
    if kind == "wrong-issuer":
        c["iss"] = "https://evil.example"
        return sign(c)
    if kind == "rogue-key":
        return sign(c, pem=ROGUE_PEM, kid=SIGNING_KID)
    if kind == "unknown-kid":
        return sign(c, pem=ROGUE_PEM, kid=uuid.uuid4().hex[:16])
    if kind == "alg-none":
        header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = b64url(json.dumps(c).encode())
        return f"{header}.{payload}."
    if kind == "hs256-confusion":
        pub_pem = SIGNING_KEY.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": SIGNING_KID}).encode())
        payload = b64url(json.dumps(c).encode())
        sig = hmac.new(pub_pem, f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()
        return f"{header}.{payload}.{b64url(sig)}"
    if kind == "no-scope":
        c["scope"] = ""
        return sign(c)
    raise KeyError(kind)


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------

@app.post("/token")
def token():
    grant = form_value("grant_type")
    if grant != "client_credentials":
        return oauth_error("unsupported_grant_type",
                           "Only grant_type=client_credentials is supported.")
    cid, rec = authenticate_client()
    if not rec:
        return oauth_error("invalid_client", "Client authentication failed.", 401,
                           {"WWW-Authenticate": 'Basic realm="token"'})
    scopes, err = resolve_scope(rec)
    if err:
        return oauth_error("invalid_scope", err)
    app.logger.info("token issued client=%s scope=%s", cid, " ".join(scopes))
    return token_response(sign(base_claims(cid, rec, scopes)), scopes)


@app.post("/test-token")
def test_token():
    cid, rec = authenticate_client()
    if not rec:
        return oauth_error("invalid_client", "Client authentication failed.", 401,
                           {"WWW-Authenticate": 'Basic realm="token"'})
    kind = form_value("kind")
    if kind not in BAD_KINDS:
        return oauth_error("invalid_request",
                           f"kind must be one of: {', '.join(BAD_KINDS)}")
    scopes, err = resolve_scope(rec)
    if err:
        return oauth_error("invalid_scope", err)
    app.logger.info("test token client=%s kind=%s", cid, kind)
    return token_response(make_bad_token(kind, cid, rec, scopes), scopes,
                          kind=kind, expect=BAD_KINDS[kind])


@app.get("/test-token/kinds")
def test_token_kinds():
    return jsonify(BAD_KINDS)


@app.get("/jwks.json")
def jwks_route():
    resp = jsonify(jwks())
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@app.get("/.well-known/oauth-authorization-server")
def metadata():
    base = request.host_url.rstrip("/")
    return jsonify({
        "issuer": ISSUER,
        "token_endpoint": f"{base}/token",
        "jwks_uri": f"{base}/jwks.json",
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ALL_SCOPES,
    })


@app.errorhandler(404)
@app.errorhandler(405)
def http_error(e):
    return jsonify({"error": e.name.lower().replace(" ", "_"),
                    "error_description": e.description}), e.code


@app.get("/health")
def health():
    return jsonify({"status": "ok", "issuer": ISSUER, "keys": len(KEYS)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9000")))
