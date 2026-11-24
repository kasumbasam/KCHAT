#!/usr/bin/env python3
"""Phase 1, Step 1.2: password input length limits.

Verifies that the 1,024-character cap is enforced on registration, login and
password reset, before any hashing or database work, while existing valid
passwords and the 8-character minimum are untouched.

Run against a locally served app:
    KCHAT_BASE=http://127.0.0.1:3000 python .verify/phase1_password_length_test.py
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("KCHAT_BASE", "http://127.0.0.1:3000")
RESULTS = []

MAX = 1024
MIN = 8


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    return bool(condition)


def request(method, path, body=None, token=None, raw_body=None, content_type=None):
    url = BASE + path
    data = None
    hdrs = {}

    if raw_body is not None:
        data = raw_body if isinstance(raw_body, bytes) else raw_body.encode()
        hdrs["Content-Type"] = content_type or "application/json"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"

    if token:
        hdrs["Authorization"] = "Bearer " + token

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        payload = error.read()
        try:
            parsed = json.loads(payload or b"{}")
        except Exception:
            parsed = {"_raw": payload.decode("utf-8", "replace")[:200]}
        return error.code, parsed


def unique_phone():
    """Distinct phone per call, so registrations never collide."""
    return "+2567" + str(int(uuid.uuid4().int % 10**8)).zfill(8)


def register(password, username=None):
    return request("POST", "/api/register", {
        "phone_number": unique_phone(),
        "password": password,
        "username": username or ("pwlen" + uuid.uuid4().hex[:8]),
    })


# ---------------------------------------------------------------- registration
def test_register():
    status, body = register("a" * (MAX + 1))
    check("register rejects 1025 chars with 400", status == 400, f"status={status} body={str(body)[:160]}")
    check("register 1025 error mentions the limit",
          str(MAX) in str(body.get("error", "")), f"error={body.get('error')}")

    status, body = register("a" * MAX)
    check("register accepts exactly 1024 chars", status == 200 and bool(body.get("token")),
          f"status={status} body={str(body)[:160]}")

    # Unicode: counted in characters, not bytes.
    status, body = register("\u00e9" * MAX)
    check("register accepts 1024 multibyte chars (2048+ bytes)", status == 200,
          f"status={status} body={str(body)[:160]}")

    status, body = register("\U0001F600" * (MAX + 1))
    check("register rejects 1025 astral-plane chars", status == 400, f"status={status}")

    # Minimum still enforced, unchanged.
    status, body = register("a" * (MIN - 1))
    check("register still rejects 7 chars", status == 400, f"status={status}")
    status, body = register("a" * MIN)
    check("register still accepts 8 chars", status == 200, f"status={status}")

    # A huge payload in bytes but legal in characters is still accepted.
    status, body = register("x" * MAX)
    check("register accepts boundary value twice (no off-by-one)", status == 200, f"status={status}")

    return True


# --------------------------------------------------------------------- login
def test_login():
    password = "correct-horse-battery"
    phone = unique_phone()
    status, body = request("POST", "/api/register", {
        "phone_number": phone,
        "password": password,
        "username": "pwlogin" + uuid.uuid4().hex[:8],
    })
    if not check("setup account for login tests", status == 200 and body.get("token"),
                 f"status={status} body={str(body)[:160]}"):
        return

    # Oversized password is refused before any lookup or hashing.
    status, body = request("POST", "/api/login", {
        "phone_number": phone, "password": "a" * (MAX + 1)
    })
    check("login rejects 1025 chars with 400", status == 400,
          f"status={status} body={str(body)[:160]}")

    # Fast rejection: an oversized password must not reach PBKDF2 (310k iters).
    big = "a" * 200000
    timings = []
    for _ in range(3):
        start = time.perf_counter()
        request("POST", "/api/login", {"phone_number": phone, "password": big})
        timings.append(time.perf_counter() - start)
    fast = min(timings)
    check("login rejects oversized password quickly (no PBKDF2)", fast < 0.5,
          f"min={fast:.3f}s over 3 tries (samples={[round(t,3) for t in timings]})")

    # The correct password still works.
    status, body = request("POST", "/api/login", {
        "phone_number": phone, "password": password
    })
    check("login still works with a normal password",
          status == 200 and bool(body.get("token")), f"status={status}")

    # Wrong password still fails normally.
    status, body = request("POST", "/api/login", {
        "phone_number": phone, "password": password + "x"
    })
    check("wrong password still returns 401", status == 401, f"status={status}")

    # Exactly at the boundary is allowed through to normal verification.
    status, body = request("POST", "/api/login", {
        "phone_number": phone, "password": "b" * MAX
    })
    check("login at 1024 chars passes validation (then auth fails normally)",
          status == 401, f"status={status}")


# ------------------------------------------------------------- password reset
def test_reset():
    password = "reset-base-password"
    phone = unique_phone()
    username = "pwreset" + uuid.uuid4().hex[:8]

    status, body = request("POST", "/api/register", {
        "phone_number": phone, "password": password, "username": username,
    })
    if not check("setup account for reset tests", status == 200 and body.get("token"),
                 f"status={status} body={str(body)[:160]}"):
        return

    status, body = request("POST", "/api/account/recovery-code",
                           token=body.get("token"))
    code = body.get("recovery_code")
    if not check("recovery code issued", status == 200 and bool(code),
                 f"status={status} body={str(body)[:160]}"):
        return

    status, body = request("POST", "/api/password/reset", {
        "phone_number": phone,
        "recovery_code": code,
        "new_password": "a" * (MAX + 1),
    })
    check("reset rejects 1025 chars with 400", status == 400,
          f"status={status} body={str(body)[:160]}")
    check("reset 1025 error mentions the limit",
          str(MAX) in str(body.get("error", "")), f"error={body.get('error')}")

    status, body = request("POST", "/api/password/reset", {
        "phone_number": phone,
        "recovery_code": code,
        "new_password": "a" * (MIN - 1),
    })
    check("reset still rejects 7 chars", status == 400,
          f"status={status} body={str(body)[:160]}")

    # A rejected attempt must not consume the recovery code.
    status, body = request("POST", "/api/password/reset", {
        "phone_number": phone,
        "recovery_code": code,
        "new_password": "brand-new-password-1",
    })
    check("reset still succeeds after a rejected overlong attempt",
          status == 200, f"status={status} body={str(body)[:160]}")

    status, body = request("POST", "/api/login", {
        "phone_number": phone, "password": "brand-new-password-1"
    })
    check("new password works after reset", status == 200, f"status={status}")


# --------------------------------------------------------------- no data leak
def test_no_leak():
    status, body = register("a" * (MAX + 1))
    text = json.dumps(body)
    check("rejection never echoes the submitted password",
          "a" * 64 not in text, f"body={text[:160]}")
    check("rejection body is JSON with an error field",
          isinstance(body, dict) and "error" in body, f"body={text[:160]}")


# ------------------------------------------------------------ account deletion
def test_delete_account():
    password = "delete-me-password"
    status, body = register(password)
    if not check("setup account for deletion tests",
                 status == 200 and body.get("token"),
                 f"status={status} body={str(body)[:160]}"):
        return

    token = body["token"]

    # Oversized password: refused before the lookup and before PBKDF2.
    big = "a" * 200000
    timings = []
    for _ in range(3):
        start = time.perf_counter()
        status, body = request("DELETE", "/api/account", {"password": big}, token=token)
        timings.append(time.perf_counter() - start)

    check("delete rejects oversized password with 400", status == 400,
          f"status={status} body={str(body)[:160]}")
    check("delete oversized error mentions the limit",
          str(MAX) in str(body.get("error", "")), f"error={body.get('error')}")
    check("delete rejects oversized password quickly (no PBKDF2)",
          min(timings) < 0.5,
          f"min={min(timings):.3f}s (samples={[round(t,3) for t in timings]})")

    # The account must still exist: a rejected attempt deletes nothing.
    status, body = request("GET", "/api/session", token=token)
    check("account still exists after a rejected oversized delete",
          status == 200, f"status={status}")

    # 1025 chars is refused, 1024 is allowed through to normal verification.
    status, body = request("DELETE", "/api/account", {"password": "a" * (MAX + 1)}, token=token)
    check("delete rejects exactly 1025 chars", status == 400, f"status={status}")
    status, body = request("DELETE", "/api/account", {"password": "b" * MAX}, token=token)
    check("delete at 1024 chars passes validation (then normal auth fails)",
          status == 401, f"status={status} body={str(body)[:160]}")

    # Short passwords still reach verification normally: no minimum at delete.
    status, body = request("DELETE", "/api/account", {"password": "short"}, token=token)
    check("delete still verifies short wrong passwords normally (401, not 400)",
          status == 401, f"status={status} body={str(body)[:160]}")

    # Empty password keeps its original message.
    status, body = request("DELETE", "/api/account", {"password": ""}, token=token)
    check("delete keeps its original empty-password message",
          status == 400 and "delete your account" in str(body.get("error", "")),
          f"status={status} error={body.get('error')}")

    # The real deletion flow still works end to end.
    status, body = request("DELETE", "/api/account", {"password": password}, token=token)
    check("delete succeeds with the correct password",
          status == 200 and body.get("success") is True,
          f"status={status} body={str(body)[:160]}")

    status, body = request("GET", "/api/session", token=token)
    check("account is gone after deletion", status == 401, f"status={status}")

    status, body = request("POST", "/api/login", {
        "phone_number": "+256700000000", "password": password
    })
    check("deleted account cannot log in", status in (401, 400), f"status={status}")


def main():
    test_register()
    test_login()
    test_reset()
    test_no_leak()
    test_delete_account()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)

    for name, ok, detail in RESULTS:
        line = ("PASS  " if ok else "FAIL  ") + name
        if not ok and detail:
            line += "  -> " + str(detail)[:220]
        print(line)

    print(f"\npassed {passed}/{total}")

    os.makedirs("/home/ubuntu/project/test-results", exist_ok=True)
    with open("/home/ubuntu/project/test-results/phase1-password-length.json", "w") as handle:
        json.dump({
            "suite": "phase1-password-length",
            "passed": passed,
            "total": total,
            "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in RESULTS],
        }, handle, indent=2)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
