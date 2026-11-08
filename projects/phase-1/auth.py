"""
Phase 1: bearer token checking for your Flask API.

Put this file next to your app.py and protect a route like this:

    from auth import require_scope

    @app.get("/data")
    @require_scope("data:read")
    def read_data():
        ...

Most of the plumbing is written for you. The parts marked TODO are yours.
Do not change the function names or what they return, because the rest of
this file depends on them.
"""

import functools
import os

import jwt  # PyJWT. Install it as PyJWT[crypto] so RS256 works.
from flask import jsonify, request

# Req. 10: these come from the environment (set in docker-compose.yml).
JWKS_URL = os.environ.get("JWKS_URL")
ISSUER = os.environ.get("ISSUER")
AUDIENCE = os.environ.get("AUDIENCE")

# Req. 7: a little clock drift between machines is normal.
LEEWAY_SECONDS = 30

_jwks_client = None


class InvalidToken(Exception):
    """The token is malformed, expired, signed wrongly, or otherwise not
    acceptable. The caller turns this into a 401."""


class KeysUnavailable(Exception):
    """The signing keys could not be obtained (for example the authorization
    server is unreachable). Never accept a token you cannot verify. The caller
    turns this into a 503."""


# ----------------------------------------------------------------------
# Provided for you
# ----------------------------------------------------------------------

def challenge(error=None, scope=None):
    """Build the value of a WWW-Authenticate header (RFC 6750)."""
    parts = ['Bearer realm="cs453"']
    if error:
        parts.append(f'error="{error}"')
    if scope:
        parts.append(f'scope="{scope}"')
    return ", ".join(parts)


def error_response(status, error, description, www_authenticate):
    """A JSON error body plus the WWW-Authenticate header."""
    resp = jsonify({"error": error, "error_description": description})
    resp.status_code = status
    resp.headers["WWW-Authenticate"] = www_authenticate
    return resp


def extract_bearer_token():
    """Return the token from 'Authorization: Bearer <token>', or None if the
    header is missing or is not a Bearer header."""
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


# ----------------------------------------------------------------------
# TODO: your part
# ----------------------------------------------------------------------

def get_signing_key(token):
    """Return the public key that should verify this token.

    TODO (Req. 9): find the key in the authorization server's JWKS (the
    address in JWKS_URL). Read the token's header WITHOUT trusting it yet to
    learn its `kid`, then pick the matching key. Requirements:

      - Do not download the JWKS on every request. Cache it.
      - If the token's `kid` is not in your cache, refetch the JWKS once
        before giving up. This is how key rotation stays painless.
      - A token with no usable `kid`, or a `kid` that still is not found
        after the refetch, is an InvalidToken.
      - If the JWKS cannot be fetched at all, raise KeysUnavailable.
      - This function runs at request time, never at import time, so your
        API still starts when the authorization server is down (Req. 11).

    Two ways to do it: write the fetch and cache yourself with urllib and
    PyJWT's key loading helpers, or read the PyJWT documentation for a
    built-in JWKS client. Either is acceptable. Reference:
    https://pyjwt.readthedocs.io/en/stable/usage.html#retrieve-rsa-signing-keys-from-a-jwks-endpoint
    The deck slides "Access Token Formats: Opaque vs. JWT" and "Step 5:
    Token Validation and Response" explain what you are looking up and why.
    """
    global _jwks_client
    if not JWKS_URL:
        raise KeysUnavailable("JWKS_URL is not set")
    if _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=300, timeout=3)
    try:
        return _jwks_client.get_signing_key_from_jwt(token).key
    except jwt.PyJWKClientConnectionError as exc:
        raise KeysUnavailable(str(exc))
    except (jwt.PyJWKClientError, jwt.PyJWTError) as exc:
        raise InvalidToken(str(exc))


def validate_token(token):
    """Verify the token and return its claims (a dict).

    TODO (Req. 7, 8): decode the token with PyJWT, using the key from
    get_signing_key. Decide for yourself, and be able to defend in your
    reflection, each argument you pass:

      - Which signature algorithms will you accept? (Req. 8: the answer is
        exactly one, and it is not 'whatever the token says'.)
      - Which issuer and audience must the token carry?
      - How much clock leeway do you allow?
      - Which claims must be present, so a token that simply omits `exp`
        does not slip through?

    Anything PyJWT rejects should become an InvalidToken. Do NOT use options
    that switch off signature or claim verification.
    """
    if not ISSUER or not AUDIENCE:
        raise KeysUnavailable("ISSUER and AUDIENCE must be set")
    key = get_signing_key(token)
    try:
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidToken(str(exc))


def has_scope(claims, required):
    """Return True if the token's scope claim includes `required`.

    TODO (Req. 5): the `scope` claim is one string with scopes separated by
    spaces, for example "data:read data:write". Decide what a token with no
    scope claim, or an empty one, should mean. The slide "Tokens, Scopes,
    and Permissions" covers the idea.
    """
    scope = claims.get("scope")
    if not isinstance(scope, str):
        return False
    return required in scope.split()


# ----------------------------------------------------------------------
# Provided: the decorator that ties it together
# ----------------------------------------------------------------------

def require_scope(required):
    """Decorator: the request must carry a valid token that has `required`."""

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            token = extract_bearer_token()
            if token is None:
                # No credentials at all: a bare Bearer challenge, no error code.
                return error_response(401, "unauthorized", "Bearer token required.", challenge())
            try:
                claims = validate_token(token)
            except InvalidToken as exc:
                return error_response(401, "invalid_token", str(exc), challenge("invalid_token"))
            except KeysUnavailable:
                return error_response(503, "temporarily_unavailable",
                                      "Cannot reach the authorization server to verify tokens.",
                                      challenge())
            except NotImplementedError as exc:
                return error_response(501, "not_implemented", str(exc), challenge())
            try:
                allowed = has_scope(claims, required)
            except NotImplementedError as exc:
                return error_response(501, "not_implemented", str(exc), challenge())
            if not allowed:
                return error_response(403, "insufficient_scope",
                                      f"This request requires scope {required}.",
                                      challenge("insufficient_scope", scope=required))
            return view(*args, **kwargs)

        return wrapper

    return decorator
