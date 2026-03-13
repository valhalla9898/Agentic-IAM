#!/usr/bin/env python3
"""Generate a signed reports URL locally using the configured signing key.

Usage:
  python scripts/generate_signed_url.py --path /reports/static/target/ts/file.html --expires 3600

The script looks for STATIC_URL_SIGNING_KEY or ADMIN_API_KEY in the environment.
"""
import os
import sys
import time
import hmac
import hashlib
from urllib.parse import quote


def sign(path: str, expires_in: int, key: str) -> str:
    exp = int(time.time()) + int(expires_in)
    msg = f"{path}|{exp}".encode("utf-8")
    sig = hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    # Build relative URL (caller can prefix host)
    return f"{path}?expires={exp}&sig={sig}"


def main():
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--path", required=True, help="Path under /reports/static to sign")
    p.add_argument("--expires", type=int, default=3600, help="Seconds until expiry")
    p.add_argument("--host", default=os.getenv("API_HOST", "http://127.0.0.1:8000"), help="Base host (with scheme)")
    args = p.parse_args()

    key = os.getenv("STATIC_URL_SIGNING_KEY") or os.getenv("ADMIN_API_KEY")
    if not key:
        print("Error: STATIC_URL_SIGNING_KEY or ADMIN_API_KEY must be set in environment", file=sys.stderr)
        sys.exit(2)

    signed = sign(args.path, args.expires, key)
    print(args.host.rstrip("/") + signed)


if __name__ == "__main__":
    main()
