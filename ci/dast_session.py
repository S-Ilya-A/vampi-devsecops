#!/usr/bin/env python3
"""Prepare an authenticated DAST session against the staging API.

usage: dast_session.py API_BASE_URL TOKEN_FILE SPEC_FILE

Does what the pen testers did before scanning (docs/PENTEST_SUMMARY.md):
  - registers its own unprivileged user (random name and password, per run);
  - logs in and writes the bearer token to TOKEN_FILE (never to the job log);
  - creates a book whose title contains markup, so the stored-XSS path (PT-07)
    has data in it for anything that renders book titles;
  - saves the OpenAPI definition the deployed API serves, with its server URL
    set to API_BASE_URL and without /createdb, to SPEC_FILE for ZAP to import. (zap-api-scan's -O does
    not work with a host name: Python's urlparse reads "host:port" as a scheme.)
Uses only the standard library, so it runs in the ZAP image as is.
"""
import json
import secrets
import sys
import urllib.request


def call(base, method, path, body=None, token=None):
    req = urllib.request.Request(base.rstrip("/") + path, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data=data, timeout=30) as r:
        return r.status, json.loads(r.read() or b"{}")


def main():
    base, token_file, spec_file = sys.argv[1], sys.argv[2], sys.argv[3]
    user = "dast" + secrets.token_hex(4)
    password = secrets.token_urlsafe(18)
    email = user + "@dast.northwind.test"

    status, body = call(base, "POST", "/users/v1/register",
                        {"username": user, "password": password, "email": email})
    print("register %s: %s %s" % (user, status, body.get("status")))
    status, body = call(base, "POST", "/users/v1/login", {"username": user, "password": password})
    token = body.get("auth_token")
    if not token:
        sys.exit("login failed: %s" % body)
    print("login: %s" % status)

    probe = "dast-%s <img src=x onerror=alert(document.domain)>" % secrets.token_hex(3)
    status, _ = call(base, "POST", "/books/v1",
                     {"book_title": probe, "secret": "dast canary"}, token=token)
    print("seeded book with markup in its title: %s" % status)

    with open(token_file, "w", encoding="utf-8") as f:
        f.write(token)

    with urllib.request.urlopen(base.rstrip("/") + "/openapi.json", timeout=30) as r:
        spec = json.loads(r.read())
    spec["servers"] = [{"url": base.rstrip("/")}]
    # /createdb drops and re-seeds the database. Called mid-scan it deletes this
    # session's user, and every authenticated request after it fails with 500, so
    # it is not scanned. (Its exposure, PT-08, needs no scanner: the deploy job
    # calls it without credentials.)
    spec["paths"].pop("/createdb", None)
    with open(spec_file, "w", encoding="utf-8") as f:
        json.dump(spec, f)
    print("OpenAPI definition: %d paths, server %s" % (len(spec.get("paths", {})), base))


if __name__ == "__main__":
    main()
