#!/usr/bin/env python3
"""
Get an access token from the authorization server.

  export AUTH_URL=http://AUTH_HOST:AUTH_PORT
  export CLIENT_ID=...  CLIENT_SECRET=...

  python3 get_token.py                          # both scopes, prints only the token
  python3 get_token.py --scope data:read        # read-only token
  python3 get_token.py --decode                 # show what is inside, instead of the token
  python3 get_token.py --bad expired            # a token your API must reject

Use it inside a command:

  TOKEN=$(python3 get_token.py)
  curl -i -H "Authorization: Bearer $TOKEN" http://localhost:5000/data

--bad kinds: see GET $AUTH_URL/test-token/kinds
Tokens last 20 minutes. When one expires, run this again.
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def b64url_json(part):
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", default="data:read data:write", help="space separated scopes (default: both)")
    ap.add_argument("--bad", metavar="KIND", help="ask for a deliberately bad token of this kind")
    ap.add_argument("--decode", action="store_true", help="print the token's header and claims instead of the token")
    args = ap.parse_args()

    auth = os.environ.get("AUTH_URL")
    cid, secret = os.environ.get("CLIENT_ID"), os.environ.get("CLIENT_SECRET")
    missing = [n for n, v in (("AUTH_URL", auth), ("CLIENT_ID", cid), ("CLIENT_SECRET", secret)) if not v]
    if missing:
        sys.exit("Set these environment variables first: " + ", ".join(missing))

    form = {"client_id": cid, "client_secret": secret, "scope": args.scope}
    if args.bad:
        path, form["kind"] = "/test-token", args.bad
    else:
        path, form["grant_type"] = "/token", "client_credentials"
    req = urllib.request.Request(auth.rstrip("/") + path, data=urllib.parse.urlencode(form).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"Authorization server said {e.code}: {e.read().decode(errors='replace')}")
    except urllib.error.URLError as e:
        sys.exit(f"Could not reach {auth}: {e.reason}")

    token = body["access_token"]
    if args.decode:
        header, payload, _ = (token.split(".") + ["", ""])[:3]
        print("header:", json.dumps(b64url_json(header), indent=2))
        print("claims:", json.dumps(b64url_json(payload), indent=2))
        print("\nNobody verified a signature here. Anyone can read these claims.")
    else:
        print(token)


if __name__ == "__main__":
    main()
