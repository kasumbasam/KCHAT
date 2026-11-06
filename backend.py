import os
import uuid
import hashlib
import secrets
import base64
import re

import psycopg
from psycopg.rows import dict_row

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.websockets import WebSocketState

app = FastAPI()

DATABASE_URL = os.environ.get("DATABASE_URL")
connected_users = {}


# ---------------- DATABASE ----------------

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        prepare_threshold=None,
        connect_timeout=15
    )


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                username_key TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        conn.execute("""
            ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS profile_picture TEXT
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id BIGSERIAL PRIMARY KEY,
                account_id BIGINT REFERENCES accounts(id)
                    ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id BIGSERIAL PRIMARY KEY,
                owner_id BIGINT REFERENCES accounts(id)
                    ON DELETE CASCADE,
                contact_id BIGINT REFERENCES accounts(id)
                    ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(owner_id, contact_id),
                CHECK(owner_id != contact_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                room TEXT NOT NULL,
                username TEXT NOT NULL,
                recipient TEXT,
                text TEXT NOT NULL,
                status TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN IF NOT EXISTS reply_to TEXT
        """)

        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS messages_room_idx
            ON messages(room, created_at)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS messages_recipient_idx
            ON messages(room, recipient, status)
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                room TEXT UNIQUE NOT NULL,
                owner_id BIGINT REFERENCES accounts(id)
                    ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                id BIGSERIAL PRIMARY KEY,
                group_id TEXT REFERENCES chat_groups(id)
                    ON DELETE CASCADE,
                account_id BIGINT REFERENCES accounts(id)
                    ON DELETE CASCADE,
                joined_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(group_id, account_id)
            )
        """)


@app.on_event("startup")
async def startup():
    init_db()


# ---------------- PASSWORD SECURITY ----------------

def hash_password(password):
    salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        310000
    )

    return (
        base64.b64encode(salt).decode() + "$" +
        base64.b64encode(hashed).decode()
    )


def verify_password(password, stored):
    try:
        salt_text, hash_text = stored.split("$")
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(hash_text)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            310000
        )

        return secrets.compare_digest(actual, expected)

    except Exception:
        return False


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(account_id):
    token = secrets.token_urlsafe(32)

    with get_db() as conn:
        conn.execute("""
            INSERT INTO sessions (account_id, token_hash, expires_at)
            VALUES (%s, %s, NOW() + INTERVAL '30 days')
        """, (account_id, token_hash(token)))

    return token


def get_account_from_token(token):
    if not token:
        return None

    with get_db() as conn:
        return conn.execute("""
            SELECT accounts.id, accounts.username
            FROM sessions
            JOIN accounts ON accounts.id = sessions.account_id
            WHERE sessions.token_hash = %s
            AND sessions.expires_at > NOW()
        """, (token_hash(token),)).fetchone()


def get_account_from_request(request):
    authorization = request.headers.get("Authorization", "")
    token = authorization.replace("Bearer ", "", 1)
    return get_account_from_token(token)


# ---------------- REGISTRATION AND LOGIN ----------------

@app.post("/api/register")
async def register(request: Request):
    try:
        data = await request.json()

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            return JSONResponse(
                {"error": "Username must be 3-30 characters using letters, numbers or underscores."},
                status_code=400
            )

        if len(password) < 8:
            return JSONResponse(
                {"error": "Password must contain at least 8 characters."},
                status_code=400
            )

        with get_db() as conn:
            account = conn.execute("""
                INSERT INTO accounts
                    (username, username_key, password_hash)
                VALUES (%s, %s, %s)
                RETURNING id, username
            """, (
                username,
                username.lower(),
                hash_password(password)
            )).fetchone()

        token = create_session(account["id"])

        return {
            "token": token,
            "username": account["username"]
        }

    except psycopg.errors.UniqueViolation:
        return JSONResponse(
            {"error": "That username is already taken."},
            status_code=409
        )

    except Exception as error:
        print("Registration error:", error)
        return JSONResponse(
            {"error": "Registration failed. Please try again."},
            status_code=500
        )


@app.post("/api/login")
async def login(request: Request):
    try:
        data = await request.json()

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        with get_db() as conn:
            account = conn.execute("""
                SELECT id, username, password_hash
                FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

        if not account or not verify_password(
            password, account["password_hash"]
        ):
            return JSONResponse(
                {"error": "Incorrect username or password."},
                status_code=401
            )

        token = create_session(account["id"])

        return {
            "token": token,
            "username": account["username"]
        }

    except Exception as error:
        print("Login error:", error)
        return JSONResponse(
            {"error": "Login failed. Please try again."},
            status_code=500
        )


# ---------------- CONTACT MANAGEMENT ----------------

@app.get("/api/contacts")
async def contacts(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    with get_db() as conn:
        rows = conn.execute("""
            SELECT accounts.username
            FROM contacts
            JOIN accounts
                ON accounts.id = contacts.contact_id
            WHERE contacts.owner_id = %s
            ORDER BY accounts.username
        """, (account["id"],)).fetchall()

    return {
        "contacts": [row["username"] for row in rows]
    }


@app.post("/api/contacts")
async def add_contact(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()

        if not username:
            return JSONResponse(
                {"error": "Enter a username."},
                status_code=400
            )

        with get_db() as conn:
            target = conn.execute("""
                SELECT id, username
                FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not target:
                return JSONResponse(
                    {"error": "No KCHAT account found with that username."},
                    status_code=404
                )

            if target["id"] == account["id"]:
                return JSONResponse(
                    {"error": "You cannot add yourself."},
                    status_code=400
                )

            conn.execute("""
                INSERT INTO contacts (owner_id, contact_id)
                VALUES (%s, %s)
                ON CONFLICT (owner_id, contact_id) DO NOTHING
            """, (account["id"], target["id"]))

        return {
            "success": True,
            "username": target["username"],
            "message": "Contact added successfully."
        }

    except Exception as error:
        print("Add contact error:", error)
        return JSONResponse(
            {"error": "Could not add contact."},
            status_code=500
        )


@app.delete("/api/contacts/{username}")
async def remove_contact(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    with get_db() as conn:
        target = conn.execute("""
            SELECT id FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

        if not target:
            return JSONResponse(
                {"error": "Contact not found."},
                status_code=404
            )

        result = conn.execute("""
            DELETE FROM contacts
            WHERE owner_id = %s AND contact_id = %s
            RETURNING id
        """, (account["id"], target["id"])).fetchone()

    if not result:
        return JSONResponse(
            {"error": "That user is not in your contacts."},
            status_code=404
        )

    return {
        "success": True,
        "message": "Contact removed."
    }


# ---------------- PROFILE PICTURES ----------------

@app.get("/api/profile/{username}")
async def get_profile(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    with get_db() as conn:
        profile = conn.execute("""
            SELECT username, profile_picture
            FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

    if not profile:
        return JSONResponse(
            {"error": "User not found."},
            status_code=404
        )

    return {
        "username": profile["username"],
        "profile_picture": profile["profile_picture"]
    }


@app.put("/api/profile")
async def update_profile(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    try:
        data = await request.json()
        picture = data.get("profile_picture")

        if picture is not None:
            if not isinstance(picture, str):
                return JSONResponse(
                    {"error": "Invalid picture."},
                    status_code=400
                )

            if len(picture) > 2_500_000:
                return JSONResponse(
                    {"error": "Picture is too large. Choose a smaller image."},
                    status_code=413
                )

            if not re.fullmatch(
                r"data:image/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+",
                picture
            ):
                return JSONResponse(
                    {"error": "Use a PNG, JPG or WEBP image."},
                    status_code=400
                )

        with get_db() as conn:
            conn.execute("""
                UPDATE accounts
                SET profile_picture = %s
                WHERE id = %s
            """, (picture, account["id"]))

        return {
            "success": True,
            "message": "Profile picture updated."
        }

    except Exception as error:
        print("Profile update error:", error)
        return JSONResponse(
            {"error": "Could not update profile picture."},
            status_code=500
        )


# ---------------- GROUP MANAGEMENT ----------------

@app.get("/api/groups")
async def get_groups(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    with get_db() as conn:
        rows = conn.execute("""
            SELECT g.id, g.name, g.room, a.username AS owner
            FROM chat_groups g
            JOIN group_members gm ON gm.group_id = g.id
            JOIN accounts a ON a.id = g.owner_id
            WHERE gm.account_id = %s
            ORDER BY g.created_at DESC
        """, (account["id"],)).fetchall()

    return {"groups": rows}


@app.post("/api/groups")
async def create_group(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    try:
        data = await request.json()
        name = str(data.get("name", "")).strip()[:50]

        if not name:
            return JSONResponse(
                {"error": "Enter a group name."},
                status_code=400
            )

        group_id = uuid.uuid4().hex
        room = "group_" + group_id

        with get_db() as conn:
            conn.execute("""
                INSERT INTO chat_groups (id, name, room, owner_id)
                VALUES (%s, %s, %s, %s)
            """, (group_id, name, room, account["id"]))

            conn.execute("""
                INSERT INTO group_members (group_id, account_id)
                VALUES (%s, %s)
            """, (group_id, account["id"]))

        return {
            "success": True,
            "id": group_id,
            "name": name,
            "room": room
        }

    except Exception as error:
        print("Create group error:", error)
        return JSONResponse(
            {"error": "Could not create group."},
            status_code=500
        )


@app.post("/api/groups/{group_id}/members")
async def add_group_member(group_id: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()

        if not username:
            return JSONResponse(
                {"error": "Enter a username."},
                status_code=400
            )

        with get_db() as conn:
            group = conn.execute("""
                SELECT id FROM chat_groups
                WHERE id = %s AND owner_id = %s
            """, (group_id, account["id"])).fetchone()

            if not group:
                return JSONResponse(
                    {"error": "Only the group owner can add members."},
                    status_code=403
                )

            target = conn.execute("""
                SELECT id, username FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not target:
                return JSONResponse(
                    {"error": "User not found."},
                    status_code=404
                )

            conn.execute("""
                INSERT INTO group_members (group_id, account_id)
                VALUES (%s, %s)
                ON CONFLICT (group_id, account_id) DO NOTHING
            """, (group_id, target["id"]))

        return {
            "success": True,
            "username": target["username"]
        }

    except Exception as error:
        print("Add group member error:", error)
        return JSONResponse(
            {"error": "Could not add group member."},
            status_code=500
        )


@app.delete("/api/groups/{group_id}/members/{username}")
async def remove_group_member(
    group_id: str,
    username: str,
    request: Request
):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    with get_db() as conn:
        group = conn.execute("""
            SELECT id FROM chat_groups
            WHERE id = %s AND owner_id = %s
        """, (group_id, account["id"])).fetchone()

        if not group:
            return JSONResponse(
                {"error": "Only the group owner can remove members."},
                status_code=403
            )

        target = conn.execute("""
            SELECT id FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

        if not target:
            return JSONResponse(
                {"error": "User not found."},
                status_code=404
            )

        if target["id"] == account["id"]:
            return JSONResponse(
                {"error": "The group owner cannot remove themselves."},
                status_code=400
            )

        result = conn.execute("""
            DELETE FROM group_members
            WHERE group_id = %s AND account_id = %s
            RETURNING id
        """, (group_id, target["id"])).fetchone()

    if not result:
        return JSONResponse(
            {"error": "That user is not a group member."},
            status_code=404
        )

    return {"success": True, "message": "Member removed."}


@app.get("/api/groups/{group_id}/members")
async def get_group_members(group_id: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    with get_db() as conn:
        membership = conn.execute("""
            SELECT id FROM group_members
            WHERE group_id = %s AND account_id = %s
        """, (group_id, account["id"])).fetchone()

        if not membership:
            return JSONResponse(
                {"error": "You are not a member of this group."},
                status_code=403
            )

        rows = conn.execute("""
            SELECT a.username
            FROM group_members gm
            JOIN accounts a ON a.id = gm.account_id
            WHERE gm.group_id = %s
            ORDER BY a.username
        """,
