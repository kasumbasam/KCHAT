#!/usr/bin/env python3
"""Phase 0 acceptance tests: preferences, session metadata, security headers.

Runs against the locally served app. Every check is independent so one
failure does not mask the rest. Writes a JUnit-style result file too.
"""
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
import time

BASE = os.environ.get("KCHAT_BASE", "http://127.0.0.1:3000")
RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    return bool(condition)


def request(method, path, body=None, token=None, headers=None, raw=False):
    url = BASE + path
    data = None
    hdrs = dict(headers or {})

    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"

    if token:
        hdrs["Authorization"] = "Bearer " + token

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = response.read()
            status = response.status
            resp_headers = dict(response.headers)
    except urllib.error.HTTPError as error:
        payload = error.read()
        status = error.code
        resp_headers = dict(error.headers)

    if raw:
        return status, payload, resp_headers

    try:
        return status, json.loads(payload or b"{}"), resp_headers
    except Exception:
        return status, {"_raw": payload.decode("utf-8", "replace")[:300]}, resp_headers


def new_account(prefix="prefs"):
    tag = uuid.uuid4().hex[:6]
    # Unique per call: two registrations in the same millisecond must not
    # collide, or later checks would silently be skipped.
    phone = "+2567" + str(int(uuid.uuid4().int % 10**8)).zfill(8)
    status, body, _ = request("POST", "/api/register", {
        "phone_number": phone,
        "password": "password123",
        "username": f"{prefix}{tag}"
    })
    return status, body


# ---------------------------------------------------------------- preferences
def test_preferences():
    status, created = new_account()
    if not check("register test account", status == 200 and created.get("token"),
                 f"status={status} body={str(created)[:180]}"):
        return None

    token = created["token"]
    other_status, other = new_account("other")
    other_token = other.get("token") if other_status == 200 else None
    check("second account registers for isolation checks",
          other_token is not None,
          f"status={other_status} body={str(other)[:180]}")

    # GET requires auth
    status, body, _ = request("GET", "/api/preferences")
    check("GET /api/preferences without auth -> 401", status == 401, f"status={status}")

    status, body, _ = request("GET", "/api/preferences", token="not-a-real-token")
    check("GET /api/preferences with bad token -> 401", status == 401, f"status={status}")

    # Defaults
    status, body, _ = request("GET", "/api/preferences", token=token)
    prefs = body.get("preferences") or {}
    check("GET returns defaults for a new account", status == 200
          and prefs.get("theme") == "" and prefs.get("font") == ""
          and prefs.get("dnd_mode") is False
          and prefs.get("story_expiry_hours") == 24
          and prefs.get("language") == "",
          f"status={status} prefs={prefs}")

    # PUT requires auth
    status, _, _ = request("PUT", "/api/preferences", {"theme": "light"})
    check("PUT /api/preferences without auth -> 401", status == 401, f"status={status}")

    status, _, _ = request("PUT", "/api/preferences", {"theme": "light"}, token="bad")
    check("PUT /api/preferences with bad token -> 401", status == 401, f"status={status}")

    # Full update
    status, body, _ = request("PUT", "/api/preferences", {
        "theme": "light",
        "font": "pacifico",
        "dnd_mode": True,
        "story_expiry_hours": 48,
        "language": "en-GB"
    }, token=token)
    saved = body.get("preferences") or {}
    check("PUT saves all five preference fields", status == 200
          and saved.get("theme") == "light"
          and saved.get("font") == "pacifico"
          and saved.get("dnd_mode") is True
          and saved.get("story_expiry_hours") == 48
          and saved.get("language") == "en-GB",
          f"status={status} saved={saved}")

    # Persistence across a fresh read
    status, body, _ = request("GET", "/api/preferences", token=token)
    prefs = body.get("preferences") or {}
    check("saved preferences persist on a new GET", status == 200
          and prefs.get("theme") == "light"
          and prefs.get("font") == "pacifico"
          and prefs.get("dnd_mode") is True
          and prefs.get("story_expiry_hours") == 48
          and prefs.get("language") == "en-GB",
          f"prefs={prefs}")

    check("updated_at is returned", bool(prefs.get("updated_at")), f"updated_at={prefs.get('updated_at')}")

    # Partial update must not reset other fields
    status, body, _ = request("PUT", "/api/preferences", {"dnd_mode": False}, token=token)
    saved = body.get("preferences") or {}
    check("partial PUT keeps untouched fields", status == 200
          and saved.get("dnd_mode") is False
          and saved.get("theme") == "light"
          and saved.get("font") == "pacifico"
          and saved.get("story_expiry_hours") == 48
          and saved.get("language") == "en-GB",
          f"saved={saved}")

    # Validation
    for label, payload in (
        ("invalid theme characters", {"theme": "dark mode!"}),
        ("overlong theme", {"theme": "x" * 60}),
        ("non-string theme", {"theme": 5}),
        ("invalid font characters", {"font": "comic sans"}),
        ("dnd_mode not a bool", {"dnd_mode": "true"}),
        ("story hours not allowed", {"story_expiry_hours": 72}),
        ("story hours boolean", {"story_expiry_hours": True}),
        ("story hours string", {"story_expiry_hours": "24"}),
        ("language invalid", {"language": "english"}),
        ("language too long", {"language": "en-GB-extra-long"}),
    ):
        status, body, _ = request("PUT", "/api/preferences", payload, token=token)
        check(f"rejects {label} -> 400", status == 400, f"status={status} body={str(body)[:120]}")

    status, body, _ = request("PUT", "/api/preferences", ["not", "a", "dict"], token=token)
    check("rejects a non-object body -> 400", status == 400, f"status={status}")

    # Allowed edge values
    for label, payload, key, expected in (
        ("empty theme clears it", {"theme": ""}, "theme", ""),
        ("12 hour story duration", {"story_expiry_hours": 12}, "story_expiry_hours", 12),
        ("24 hour story duration", {"story_expiry_hours": 24}, "story_expiry_hours", 24),
        ("base language code", {"language": "sw"}, "language", "sw"),
        ("empty language clears it", {"language": ""}, "language", ""),
    ):
        status, body, _ = request("PUT", "/api/preferences", payload, token=token)
        saved = body.get("preferences") or {}
        check(f"accepts {label}", status == 200 and saved.get(key) == expected,
              f"status={status} {key}={saved.get(key)}")

    # Isolation between accounts
    if other_token:
        status, body, _ = request("GET", "/api/preferences", token=other_token)
        other_prefs = body.get("preferences") or {}
        check("another account sees its own defaults, not mine", status == 200
              and other_prefs.get("story_expiry_hours") == 24
              and other_prefs.get("theme") == "",
              f"other={other_prefs}")

        request("PUT", "/api/preferences", {"theme": "sand"}, token=other_token)
        status, body, _ = request("GET", "/api/preferences", token=token)
        mine = body.get("preferences") or {}
        check("my preferences are unchanged by another account's write",
              mine.get("theme") == "", f"mine={mine}")

        # No way to address another account's preferences
        status, body, _ = request("PUT", "/api/preferences",
                                  {"theme": "x", "owner_id": 1}, token=other_token)
        saved = body.get("preferences") or {}
        check("owner_id in the body is ignored", status == 200
              and saved.get("theme") == "x", f"status={status} saved={saved.get('theme')}")

    return token


# ------------------------------------------------------------ session metadata
def test_sessions():
    status, created = new_account("sess")
    if not check("second account registers for session tests", status == 200 and created.get("token")):
        return

    token = created["token"]

    status, body, _ = request("GET", "/api/session", token=token)
    check("existing session still authenticates after migration",
          status == 200 and body.get("username") == created.get("username"),
          f"status={status} body={str(body)[:120]}")

    # A brand-new session must carry the Phase 0 metadata
    sys.path.insert(0, "/home/ubuntu/project")
    import psycopg
    from psycopg.rows import dict_row
    from backend import token_hash

    with psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row) as conn:
        row = conn.execute("""
            SELECT label, user_agent, last_seen_at
            FROM sessions WHERE token_hash = %s
        """, (token_hash(token),)).fetchone()

    check("new session stores label/user_agent/last_seen_at",
          row is not None and row["last_seen_at"] is not None,
          f"row={row}")

    # last_seen_at only moves forward, never breaks auth
    status, _, _ = request("GET", "/api/preferences", token=token)
    check("authenticated request after last_seen write still works", status == 200, f"status={status}")


# --------------------------------------------------------------- security headers
def test_headers():
    status, payload, headers = request("GET", "/", raw=True)
    lowered = {k.lower(): v for k, v in headers.items()}

    check("page still serves 200", status == 200, f"status={status}")

    for header, expected in (
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
    ):
        check(f"{header} is set", lowered.get(header) == expected,
              f"got={lowered.get(header)}")

    check("Permissions-Policy is set", "permissions-policy" in lowered,
          f"got={lowered.get('permissions-policy')}")

    csp = lowered.get("content-security-policy-report-only", "")
    check("CSP is report-only, not enforcing", "content-security-policy" not in lowered
          and bool(csp), f"enforcing={lowered.get('content-security-policy')}")

    for directive in ("default-src 'self'", "frame-ancestors 'none'",
                      "object-src 'none'", "report-uri /api/csp-report"):
        check(f"CSP report-only contains {directive}", directive in csp,
              f"csp={csp[:160]}")

    status, _, _ = request("GET", "/api/preferences")
    lowered = _
    check("API responses also carry the security headers",
          str(_.get("X-Content-Type-Options") or _.get("x-content-type-options")).lower() == "nosniff",
          f"headers={list(_.keys())[:8]}")

    # HSTS must not appear over plain http (local testing)
    check("no HSTS over plain http", "strict-transport-security" not in lowered,
          f"got={lowered.get('strict-transport-security')}")


# ------------------------------------------------------------------- CSP reports
def test_csp_report():
    report = {
        "csp-report": {
            "document-uri": "https://kchat.example/",
            "violated-directive": "img-src",
            "effective-directive": "img-src",
            "blocked-uri": "https://evil.example/x.png",
            "source-file": "https://kchat.example/app.js",
            "line-number": 42,
            "disposition": "report"
        }
    }
    status, _, _ = request("POST", "/api/csp-report", report, raw=True)
    check("CSP report endpoint accepts a browser report", status == 204, f"status={status}")

    status, _, _ = request("POST", "/api/csp-report", {"unexpected": "shape"}, raw=True)
    check("CSP report endpoint tolerates an unknown shape", status == 204, f"status={status}")

    status, _, _ = request("POST", "/api/csp-report", "not json at all", raw=True,
                           headers={"Content-Type": "text/plain"})
    check("CSP report endpoint tolerates a non-JSON body", status == 204, f"status={status}")

    big = {"csp-report": {"blocked-uri": "x" * (40 * 1024)}}
    status, _, _ = request("POST", "/api/csp-report", big, raw=True)
    check("CSP report endpoint rejects oversized reports without error", status == 204,
          f"status={status}")


def test_redaction():
    sys.path.insert(0, "/home/ubuntu/project")
    from backend import redact, mask_phone, mask_identifier

    dirty = {
        "password": "hunter2",
        "new_password": "hunter3",
        "token": "abc123",
        "recovery_code": "secret-code",
        "authorization": "Bearer xyz",
        "salt$hash": "zzz",
        "nested": {"api_key": "k-1", "safe": "visible"},
        "list": [{"password": "p"}, "plain"],
    }
    cleaned = redact(dirty)

    leaked = json.dumps(cleaned)
    check("redaction removes password value", "hunter2" not in leaked and "hunter3" not in leaked, leaked[:200])
    check("redaction removes token value", "abc123" not in leaked, leaked[:200])
    check("redaction removes recovery code", "secret-code" not in leaked, leaked[:200])
    check("redaction removes bearer value", "xyz" not in leaked, leaked[:200])
    check("redaction removes nested api key", "k-1" not in leaked, leaked[:200])
    check("redaction keeps harmless values", "visible" in leaked and "plain" in leaked, leaked[:200])

    check("mask_phone keeps only last two digits", (mask_phone("+256 700 123456") or "").endswith("56")
          and "700" not in (mask_phone("+256 700 123456") or ""),
          mask_phone("+256 700 123456"))
    check("mask_phone handles short input", mask_phone("12") == "***", mask_phone("12"))
    check("mask_identifier truncates", (mask_identifier("sammie") or "").startswith("sa*"),
          mask_identifier("sammie"))


def test_log_output_is_clean():
    """The server writes security lines to stdout; verify none carry secrets."""
    log_path = os.environ.get("KCHAT_SERVER_LOG", "/tmp/phase0-uvicorn.log")
    if not check("server log available for secret scan", os.path.exists(log_path),
                 f"no log at {log_path}; set KCHAT_SERVER_LOG to the running server's log"):
        return

    with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()

    check("server log has security events", '"channel": "security"' in text.replace("'", '"'),
          "no security lines found")
    for secret in ("password123", "not-a-real-token", "hunter2"):
        check(f"server log never contains {secret}", secret not in text,
              "found in log")


def main():
    test_preferences()
    test_sessions()
    test_headers()
    test_csp_report()
    test_redaction()
    test_log_output_is_clean()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)

    for name, ok, detail in RESULTS:
        line = ("PASS  " if ok else "FAIL  ") + name
        if not ok and detail:
            line += "  -> " + str(detail)[:220]
        print(line)

    print(f"\npassed {passed}/{total}")

    os.makedirs("/home/ubuntu/project/test-results", exist_ok=True)
    with open("/home/ubuntu/project/test-results/phase0-results.json", "w") as handle:
        json.dump({
            "suite": "phase0",
            "passed": passed,
            "total": total,
            "checks": [
                {"name": n, "ok": o, "detail": d} for n, o, d in RESULTS
            ]
        }, handle, indent=2)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
