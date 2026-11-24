#!/usr/bin/env python3
"""Phase 1, Step 1.4: inbox phone-number privacy leak.

A blocked peer's phone number must not be returned by the inbox, in either
blocking direction, matching how profile_picture and about are already hidden.
Normal contacts must keep their number, and the response shape must not change.

Run against a locally served app:
    KCHAT_BASE=http://127.0.0.1:3000 python .verify/phase1_inbox_privacy_test.py
"""
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("KCHAT_BASE", "http://127.0.0.1:3000")
RESULTS = []

REQUIRED_KEYS = {
    "username", "profile_picture", "about", "phone_number",
    "is_saved_contact", "last_message", "last_message_id",
    "last_message_time", "last_message_sender", "last_message_status",
    "unread_count", "pinned", "hidden", "muted", "disappearing_seconds",
    "theme", "media_visibility", "wallpaper", "blocked", "restricted",
}


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    return bool(condition)


def request(method, path, body=None, token=None):
    url = BASE + path
    data = None
    hdrs = {}

    if body is not None:
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
            return error.code, json.loads(payload or b"{}")
        except Exception:
            return error.code, {"_raw": payload.decode("utf-8", "replace")[:200]}


def make_account(prefix):
    phone = "+2567" + str(int(uuid.uuid4().int % 10**8)).zfill(8)
    username = prefix + uuid.uuid4().hex[:8]
    status, body = request("POST", "/api/register", {
        "phone_number": phone,
        "password": "password123",
        "username": username,
    })
    if status != 200:
        return None
    return {
        "token": body["token"],
        "username": body["username"],
        "phone": body.get("phone_number") or phone,
    }


def send_private(from_acct, to_name, text):
    return request("POST", "/api/messages", {
        "type": "private",
        "text": text,
        "to": to_name,
    }, token=from_acct["token"])


def find(inbox, username):
    for item in inbox:
        if str(item.get("username", "")).lower() == username.lower():
            return item
    return None


def inbox_of(account, include_hidden=False):
    path = "/api/inbox" + ("?include_hidden=true" if include_hidden else "")
    status, body = request("GET", path, token=account["token"])
    return status, body.get("inbox", []), body


def test_normal_contact_keeps_number():
    alice = make_account("inb_n_")
    bob = make_account("inb_n_")
    if not check("setup: two accounts register", alice and bob):
        return

    status, body = send_private(alice, bob["username"], "hello bob")
    if not check("setup: alice can message bob", status in (200, 201),
                 f"status={status} body={str(body)[:160]}"):
        return

    status, inbox, raw = inbox_of(bob)
    item = find(inbox, alice["username"])
    if not check("normal contact appears in bob's inbox", item is not None,
                 f"inbox={[i.get('username') for i in inbox][:5]}"):
        return

    check("normal contact keeps its phone number",
          item.get("phone_number") == alice["phone"],
          f"got={item.get('phone_number')} expected={alice['phone']}")
    check("normal contact is not restricted", item.get("restricted") is False,
          f"restricted={item.get('restricted')}")
    check("normal contact is not blocked-flagged", item.get("blocked") is False,
          f"blocked={item.get('blocked')}")
    check("normal contact still shows picture/about fields",
          "profile_picture" in item and "about" in item)


def test_blocker_hides_number():
    """Bob blocks Alice: Bob's inbox must not show Alice's number."""
    alice = make_account("inb_a_")
    bob = make_account("inb_b_")
    if not check("setup: accounts for blocker case", alice and bob):
        return

    send_private(alice, bob["username"], "message before blocking")

    status, body = request("POST", "/api/blocks",
                           {"username": alice["username"]}, token=bob["token"])
    if not check("setup: bob blocks alice", status == 200,
                 f"status={status} body={str(body)[:160]}"):
        return

    status, inbox, raw = inbox_of(bob)
    item = find(inbox, alice["username"])
    if not check("blocked peer still appears in bob's inbox (history kept)",
                 item is not None,
                 f"inbox={[i.get('username') for i in inbox][:5]}"):
        return

    check("BLOCKER: peer phone number is hidden",
          item.get("phone_number") is None,
          f"leaked={item.get('phone_number')}")
    check("BLOCKER: restricted flag is true", item.get("restricted") is True,
          f"restricted={item.get('restricted')}")
    check("BLOCKER: picture also hidden (existing behaviour)",
          item.get("profile_picture") is None,
          f"picture={item.get('profile_picture')}")
    check("BLOCKER: about also hidden (existing behaviour)",
          item.get("about") == "", f"about={item.get('about')}")
    check("BLOCKER: response keeps every expected key",
          REQUIRED_KEYS.issubset(set(item.keys())),
          f"missing={sorted(REQUIRED_KEYS - set(item.keys()))}")


def test_blocked_party_hides_number():
    """Alice is blocked BY Bob: Alice's inbox must not show Bob's number."""
    alice = make_account("inb_x_")
    bob = make_account("inb_y_")
    if not check("setup: accounts for blocked-party case", alice and bob):
        return

    send_private(bob, alice["username"], "message before blocking")

    status, body = request("POST", "/api/blocks",
                           {"username": alice["username"]}, token=bob["token"])
    if not check("setup: bob blocks alice (reverse direction)", status == 200,
                 f"status={status} body={str(body)[:160]}"):
        return

    status, inbox, raw = inbox_of(alice)
    item = find(inbox, bob["username"])
    if not check("blocking party still appears in alice's inbox (history kept)",
                 item is not None,
                 f"inbox={[i.get('username') for i in inbox][:5]}"):
        return

    check("BLOCKED PARTY: peer phone number is hidden",
          item.get("phone_number") is None,
          f"leaked={item.get('phone_number')}")
    check("BLOCKED PARTY: restricted flag is true",
          item.get("restricted") is True, f"restricted={item.get('restricted')}")
    check("BLOCKED PARTY: picture also hidden",
          item.get("profile_picture") is None,
          f"picture={item.get('profile_picture')}")
    check("BLOCKED PARTY: response keeps every expected key",
          REQUIRED_KEYS.issubset(set(item.keys())),
          f"missing={sorted(REQUIRED_KEYS - set(item.keys()))}")


def test_unblock_restores_number():
    alice = make_account("inb_u_")
    bob = make_account("inb_u_")
    if not check("setup: accounts for unblock case", alice and bob):
        return

    send_private(alice, bob["username"], "hello")
    request("POST", "/api/blocks", {"username": alice["username"]}, token=bob["token"])

    status, inbox, raw = inbox_of(bob)
    item = find(inbox, alice["username"])
    check("while blocked: number hidden", item is not None and item.get("phone_number") is None,
          f"got={item.get('phone_number') if item else 'no item'}")

    status, body = request("DELETE", "/api/blocks/" + alice["username"], token=bob["token"])
    if not check("setup: bob unblocks alice", status == 200,
                 f"status={status} body={str(body)[:160]}"):
        return

    status, inbox, raw = inbox_of(bob)
    item = find(inbox, alice["username"])
    check("after unblock: number is restored",
          item is not None and item.get("phone_number") == alice["phone"],
          f"got={item.get('phone_number') if item else 'no item'}")
    check("after unblock: restricted is false again",
          item is not None and item.get("restricted") is False,
          f"restricted={item.get('restricted') if item else 'no item'}")


def test_response_shape_unchanged():
    alice = make_account("inb_s_")
    bob = make_account("inb_s_")
    if not check("setup: accounts for shape case", alice and bob):
        return

    send_private(alice, bob["username"], "shape check")

    status, body = request("GET", "/api/inbox", token=bob["token"])
    check("inbox returns the same top-level keys",
          set(body.keys()) == {"inbox", "total"}, f"keys={sorted(body.keys())}")
    check("inbox total matches list length",
          body.get("total") == len(body.get("inbox", [])), f"total={body.get('total')}")
    item = find(body.get("inbox", []), alice["username"])
    check("inbox item keeps every expected key",
          item is not None and REQUIRED_KEYS.issubset(set(item.keys())),
          f"missing={sorted(REQUIRED_KEYS - set(item.keys())) if item else 'no item'}")
    check("phone_number key is always present, never removed",
          item is not None and "phone_number" in item, "key missing")


def main():
    test_normal_contact_keeps_number()
    test_blocker_hides_number()
    test_blocked_party_hides_number()
    test_unblock_restores_number()
    test_response_shape_unchanged()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)

    for name, ok, detail in RESULTS:
        line = ("PASS  " if ok else "FAIL  ") + name
        if not ok and detail:
            line += "  -> " + str(detail)[:220]
        print(line)

    print(f"\npassed {passed}/{total}")

    os.makedirs("/home/ubuntu/project/test-results", exist_ok=True)
    with open("/home/ubuntu/project/test-results/phase1-inbox-privacy.json", "w") as handle:
        json.dump({
            "suite": "phase1-inbox-privacy",
            "passed": passed,
            "total": total,
            "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in RESULTS],
        }, handle, indent=2)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
