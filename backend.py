
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
            ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS phone_number TEXT
        """)

        conn.execute("""
            ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS phone_key TEXT
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS accounts_phone_key_idx
            ON accounts(phone_key)
            WHERE phone_key IS NOT NULL
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id BIGSERIAL PRIMARY KEY,
                account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id BIGSERIAL PRIMARY KEY,
                owner_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                contact_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
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
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
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
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                name_key TEXT UNIQUE NOT NULL,
                creator_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id BIGINT REFERENCES chat_groups(id) ON DELETE CASCADE,
                account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (group_id, account_id)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS group_members_account_idx
            ON group_members(account_id)
        """)


@app.on_event("startup")
async def startup():
    init_db()


# ---------------- PHONE NUMBER HELPERS ----------------

def normalize_phone(phone):
    phone = str(phone or "").strip()

    if not phone:
        return None

    if not re.fullmatch(r"[+0-9()\-\s]+", phone):
        return None

    has_plus = phone.startswith("+")
    digits = re.sub(r"\D", "", phone)

    if not 7 <= len(digits) <= 15:
        return None

    return ("+" if has_plus else "") + digits


def phone_key(phone):
    normalized = normalize_phone(phone)

    if not normalized:
        return None

    return re.sub(r"\D", "", normalized)


# ---------------- PROFILE PICTURE VALIDATION ----------------

def validate_picture(picture):
    if picture in (None, ""):
        return True

    if not isinstance(picture, str):
        return False

    if len(picture) > 2_500_000:
        return False

    return bool(re.fullmatch(
        r"data:image/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+",
        picture
    ))


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
        base64.b64encode(salt).decode()
        + "$"
        + base64.b64encode(hashed).decode()
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
            SELECT accounts.id, accounts.username,
                   accounts.phone_number, accounts.profile_picture
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

        phone = str(data.get("phone_number", "")).strip()
        password = str(data.get("password", ""))
        username = str(data.get("username", "")).strip()
        picture = data.get("profile_picture")

        normalized_phone = normalize_phone(phone)
        normalized_key = phone_key(phone)

        if not normalized_phone or not normalized_key:
            return JSONResponse({
                "error": "Enter a valid phone number, including its country code if possible."
            }, status_code=400)

        # USERNAME RULE:
        # Any characters are allowed, including symbols,
        # letters, numbers and spaces.
        # Only the length is restricted to 3-30 characters.
        if len(username) < 3 or len(username) > 30:
            return JSONResponse({
                "error": "Username must be between 3 and 30 characters."
            }, status_code=400)

        if len(password) < 8:
            return JSONResponse({
                "error": "Password must contain at least 8 characters."
            }, status_code=400)

        if not validate_picture(picture):
            return JSONResponse({
                "error": "Choose a valid PNG, JPG or WEBP profile picture."
            }, status_code=400)

        with get_db() as conn:
            existing_phone = conn.execute("""
                SELECT id FROM accounts
                WHERE phone_key = %s
            """, (normalized_key,)).fetchone()

            if existing_phone:
                return JSONResponse({
                    "error": "That phone number is already registered."
                }, status_code=409)

            existing_username = conn.execute("""
                SELECT id FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if existing_username:
                return JSONResponse({
                    "error": "That username is already taken."
                }, status_code=409)

            account = conn.execute("""
                INSERT INTO accounts (
                    username,
                    username_key,
                    password_hash,
                    phone_number,
                    phone_key,
                    profile_picture
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, username, phone_number
            """, (
                username,
                username.lower(),
                hash_password(password),
                normalized_phone,
                normalized_key,
                picture
            )).fetchone()

        token = create_session(account["id"])

        return {
            "success": True,
            "token": token,
            "username": account["username"],
            "phone_number": account["phone_number"]
        }

    except psycopg.errors.UniqueViolation:
        return JSONResponse({
            "error": "That phone number or username is already registered."
        }, status_code=409)

    except Exception as error:
        print("Registration error:", error)

        return JSONResponse({
            "error": "Registration failed. Please try again."
        }, status_code=500)


@app.post("/api/login")
async def login(request: Request):
    try:
        data = await request.json()

        login_value = str(
            data.get("phone_number", data.get("username", ""))
        ).strip()

        password = str(data.get("password", ""))

        if not login_value or not password:
            return JSONResponse({
                "error": "Enter your phone number and password."
            }, status_code=400)

        normalized_key = phone_key(login_value)

        with get_db() as conn:
            account = None

            if normalized_key:
                account = conn.execute("""
                    SELECT id, username, phone_number, password_hash
                    FROM accounts
                    WHERE phone_key = %s
                """, (normalized_key,)).fetchone()

            if not account:
                account = conn.execute("""
                    SELECT id, username, phone_number, password_hash
                    FROM accounts
                    WHERE username_key = %s
                """, (login_value.lower(),)).fetchone()

        if not account or not verify_password(
            password,
            account["password_hash"]
        ):
            return JSONResponse({
                "error": "Incorrect phone number or password."
            }, status_code=401)

        token = create_session(account["id"])

        return {
            "success": True,
            "token": token,
            "username": account["username"],
            "phone_number": account["phone_number"]
        }

    except Exception as error:
        print("Login error:", error)

        return JSONResponse({
            "error": "Login failed. Please try again."
        }, status_code=500)


# ---------------- CONTACT MANAGEMENT ----------------

@app.get("/api/contacts")
async def contacts(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT accounts.username
            FROM contacts
            JOIN accounts ON accounts.id = contacts.contact_id
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
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()

        if not username:
            return JSONResponse({
                "error": "Enter a username."
            }, status_code=400)

        with get_db() as conn:
            target = conn.execute("""
                SELECT id, username
                FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not target:
                return JSONResponse({
                    "error": "No KCHAT account found with that username."
                }, status_code=404)

            if target["id"] == account["id"]:
                return JSONResponse({
                    "error": "You cannot add yourself."
                }, status_code=400)

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

        return JSONResponse({
            "error": "Could not add contact."
        }, status_code=500)


@app.delete("/api/contacts/{username}")
async def remove_contact(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    with get_db() as conn:
        target = conn.execute("""
            SELECT id
            FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

        if not target:
            return JSONResponse({
                "error": "Contact not found."
            }, status_code=404)

        result = conn.execute("""
            DELETE FROM contacts
            WHERE owner_id = %s AND contact_id = %s
            RETURNING id
        """, (account["id"], target["id"])).fetchone()

    if not result:
        return JSONResponse({
            "error": "That user is not in your contacts."
        }, status_code=404)

    return {
        "success": True,
        "message": "Contact removed."
    }


# ---------------- PROFILE PICTURES ----------------

@app.get("/api/profile/{username}")
async def get_profile(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    with get_db() as conn:
        profile = conn.execute("""
            SELECT username, profile_picture
            FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

    if not profile:
        return JSONResponse({
            "error": "User not found."
        }, status_code=404)

    return {
        "username": profile["username"],
        "profile_picture": profile["profile_picture"]
    }


@app.put("/api/profile")
async def update_profile(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    try:
        data = await request.json()
        picture = data.get("profile_picture")

        if not validate_picture(picture):
            return JSONResponse({
                "error": "Use a PNG, JPG or WEBP image under the size limit."
            }, status_code=400)

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

        return JSONResponse({
            "error": "Could not update profile picture."
        }, status_code=500)


# ---------------- GROUP MANAGEMENT ----------------

@app.get("/api/groups")
async def get_groups(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                chat_groups.id,
                chat_groups.name,
                chat_groups.creator_id,
                chat_groups.created_at,
                group_members.role,
                (
                    SELECT COUNT(*)
                    FROM group_members AS members
                    WHERE members.group_id = chat_groups.id
                ) AS member_count
            FROM chat_groups
            JOIN group_members
                ON group_members.group_id = chat_groups.id
            WHERE group_members.account_id = %s
            ORDER BY chat_groups.created_at DESC
        """, (account["id"],)).fetchall()

    groups = []

    for row in rows:
        groups.append({
            "id": row["id"],
            "name": row["name"],
            "creator_id": row["creator_id"],
            "role": row["role"],
            "member_count": row["member_count"],
            "created_at": row["created_at"].isoformat()
        })

    return {"groups": groups}


@app.post("/api/groups")
async def create_group(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    try:
        data = await request.json()
        name = str(data.get("name", "")).strip()

        if len(name) < 2 or len(name) > 40:
            return JSONResponse({
                "error": "Group name must be between 2 and 40 characters."
            }, status_code=400)

        name_key = uuid.uuid4().hex

        with get_db() as conn:
            group = conn.execute("""
                INSERT INTO chat_groups (name, name_key, creator_id)
                VALUES (%s, %s, %s)
                RETURNING id, name, creator_id, created_at
            """, (
                name,
                name_key,
                account["id"]
            )).fetchone()

            conn.execute("""
                INSERT INTO group_members (group_id, account_id, role)
                VALUES (%s, %s, 'admin')
            """, (group["id"], account["id"]))

        return {
            "success": True,
            "group": {
                "id": group["id"],
                "name": group["name"],
                "creator_id": group["creator_id"],
                "role": "admin",
                "member_count": 1,
                "room": "group_" + str(group["id"]),
                "created_at": group["created_at"].isoformat()
            },
            "message": "Group created successfully."
        }

    except Exception as error:
        print("Create group error:", error)

        return JSONResponse({
            "error": "Could not create the group."
        }, status_code=500)


@app.get("/api/groups/{group_id}/members")
async def get_group_members(group_id: int, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    with get_db() as conn:
        membership = conn.execute("""
            SELECT role
            FROM group_members
            WHERE group_id = %s AND account_id = %s
        """, (group_id, account["id"])).fetchone()

        if not membership:
            return JSONResponse({
                "error": "You are not a member of this group."
            }, status_code=403)

        rows = conn.execute("""
            SELECT accounts.username, group_members.role, group_members.joined_at
            FROM group_members
            JOIN accounts ON accounts.id = group_members.account_id
            WHERE group_members.group_id = %s
            ORDER BY group_members.joined_at ASC
        """, (group_id,)).fetchall()

    return {
        "members": [
            {
                "username": row["username"],
                "role": row["role"],
                "joined_at": row["joined_at"].isoformat()
            }
            for row in rows
        ]
    }


@app.post("/api/groups/{group_id}/members")
async def add_group_member(group_id: int, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()

        if not username:
            return JSONResponse({
                "error": "Enter the username to add."
            }, status_code=400)

        with get_db() as conn:
            group = conn.execute("""
                SELECT id, creator_id
                FROM chat_groups
                WHERE id = %s
            """, (group_id,)).fetchone()

            if not group:
                return JSONResponse({
                    "error": "Group not found."
                }, status_code=404)

            if group["creator_id"] != account["id"]:
                return JSONResponse({
                    "error": "Only the group creator can add members."
                }, status_code=403)

            target = conn.execute("""
                SELECT id, username
                FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not target:
                return JSONResponse({
                    "error": "No KCHAT account found with that username."
                }, status_code=404)

            existing = conn.execute("""
                SELECT account_id
                FROM group_members
                WHERE group_id = %s AND account_id = %s
            """, (group_id, target["id"])).fetchone()

            if existing:
                return JSONResponse({
                    "error": "That user is already a member of this group."
                }, status_code=409)

            conn.execute("""
                INSERT INTO group_members (group_id, account_id, role)
                VALUES (%s, %s, 'member')
            """, (group_id, target["id"]))

        return {
            "success": True,
            "username": target["username"],
            "message": "Member added successfully."
        }

    except Exception as error:
        print("Add group member error:", error)

        return JSONResponse({
            "error": "Could not add this member."
        }, status_code=500)


@app.delete("/api/groups/{group_id}/members/{username}")
async def remove_group_member(group_id: int, username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({
            "error": "Please log in again."
        }, status_code=401)

    with get_db() as conn:
        group = conn.execute("""
            SELECT id, creator_id
            FROM chat_groups
            WHERE id = %s
        """, (group_id,)).fetchone()

        if not group:
            return JSONResponse({
                "error": "Group not found."
            }, status_code=404)

        if group["creator_id"] != account["id"]:
            return JSONResponse({
                "error": "Only the group creator can remove members."
            }, status_code=403)

        target = conn.execute("""
            SELECT id, username
            FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

        if not target:
            return JSONResponse({
                "error": "User not found."
            }, status_code=404)

        if target["id"] == group["creator_id"]:
            return JSONResponse({
                "error": "The group creator cannot be removed."
            }, status_code=400)

        result = conn.execute("""
            DELETE FROM group_members
            WHERE group_id = %s AND account_id = %s
            RETURNING account_id
        """, (group_id, target["id"])).fetchone()

    if not result:
        return JSONResponse({
            "error": "That user is not a member of this group."
        }, status_code=404)

    return {
        "success": True,
        "message": target["username"] + " was removed from the group."
    }


# ---------------- CHAT HELPERS ----------------

async def broadcast(room, message):
    disconnected = []

    for user in list(connected_users.get(room, [])):
        try:
            await user["websocket"].send_json(message)

        except Exception as error:
            print("Broadcast error:", error)
            disconnected.append(user)

    for user in disconnected:
        if user in connected_users.get(room, []):
            connected_users[room].remove(user)


def find_users(room, username):
    active = []

    for user in connected_users.get(room, []):
        websocket = user["websocket"]

        if websocket.client_state == WebSocketState.CONNECTED:
            active.append(user)

    connected_users[room] = active

    return [
        user for user in active
        if user["username"].lower() == username.lower()
    ]


def private_pair(user1, user2):
    return sorted([
        user1.lower(),
        user2.lower()
    ])


def save_message(item, room):
    with get_db() as conn:
        row = conn.execute("""
            INSERT INTO messages (
                id, type, room, username, recipient, text, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING created_at
        """, (
            item["id"],
            item["type"],
            room,
            item["username"],
            item.get("to"),
            item["text"],
            item.get("status")
        )).fetchone()

    item["created_at"] = row["created_at"].isoformat()

    return item


def message_from_row(row):
    created_at = row["created_at"]

    return {
        "id": row["id"],
        "type": row["type"],
        "username": row["username"],
        "to": row["recipient"],
        "text": row["text"],
        "status": row["status"],
        "created_at": created_at.isoformat() if created_at else None
    }


def load_group_history(room):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT *
            FROM messages
            WHERE room = %s AND type = 'chat'
            ORDER BY created_at ASC
        """, (room,)).fetchall()

    return [
        message_from_row(row)
        for row in rows
    ]


def load_private_history(room, user1, user2):
    first, second = private_pair(user1, user2)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT *
            FROM messages
            WHERE room = %s
            AND type = 'private'
            AND (
                (LOWER(username) = %s AND LOWER(recipient) = %s)
                OR
                (LOWER(username) = %s AND LOWER(recipient) = %s)
            )
            ORDER BY created_at ASC
        """, (
            room,
            first,
            second,
            second,
            first
        )).fetchall()

    return [
        message_from_row(row)
        for row in rows
    ]


async def update_sender_status(room, item):
    for sender in find_users(room, item["username"]):
        try:
            await sender["websocket"].send_json({
                "type": "private_status",
                "id": item["id"],
                "status": item["status"]
            })

        except Exception as error:
            print("Status update error:", error)


async def deliver_pending_messages(room, username, websocket):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT *
            FROM messages
            WHERE room = %s
            AND type = 'private'
            AND LOWER(recipient) = %s
            AND status = 'sent'
            ORDER BY created_at ASC
        """, (
            room,
            username.lower()
        )).fetchall()

        for row in rows:
            item = message_from_row(row)
            item["status"] = "delivered"

            await websocket.send_json(item)

            conn.execute("""
                UPDATE messages
                SET status = 'delivered'
                WHERE id = %s
            """, (item["id"],))

            await update_sender_status(room, item)


async def send_online_users(room):
    users = list(dict.fromkeys(
        user["username"]
        for user in connected_users.get(room, [])
        if user["websocket"].client_state == WebSocketState.CONNECTED
    ))

    await broadcast(room, {
        "type": "users",
        "users": users
    })


# ---------------- WEBSITE ----------------

@app.get("/")
async def home():
    return FileResponse("index.html")


# ---------------- WEBSOCKET CHAT ----------------

@app.websocket("/ws/{room}")
async def chat(websocket: WebSocket, room: str):
    await websocket.accept()

    token = websocket.query_params.get("token", "")
    account = get_account_from_token(token)

    if not account:
        await websocket.close(code=4401)
        return

    username = account["username"]
    room = room.strip()[:40] or "general"

    if room.startswith("group_"):
        group_id_text = room[6:]

        if not group_id_text.isdigit():
            await websocket.close(code=4403)
            return

        group_id = int(group_id_text)

        with get_db() as conn:
            membership = conn.execute("""
                SELECT account_id
                FROM group_members
                WHERE group_id = %s AND account_id = %s
            """, (
                group_id,
                account["id"]
            )).fetchone()

        if not membership:
            await websocket.close(code=4403)
            return

    connected_users.setdefault(room, [])

    was_online = bool(find_users(room, username))

    connected_users[room].append({
        "username": username,
        "websocket": websocket
    })

    await websocket.send_json({
        "type": "welcome",
        "history": load_group_history(room),
        "users": list(dict.fromkeys(
            user["username"]
            for user in connected_users[room]
        ))
    })

    if not was_online:
        await broadcast(room, {
            "type": "system",
            "text": username + " is online."
        })

    await send_online_users(room)

    try:
        await deliver_pending_messages(room, username, websocket)

        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")

            if message_type == "logout":
                print(username, "logged out")
                break

            if message_type == "chat":
                message = str(data.get("text", "")).strip()

                if not message:
                    continue

                item = {
                    "id": uuid.uuid4().hex,
                    "type": "chat",
                    "username": username,
                    "text": message
                }

                save_message(item, room)
                await broadcast(room, item)

            elif message_type == "open_private":
                recipient = str(data.get("to", "")).strip()[:30]

                if not recipient or recipient.lower() == username.lower():
                    continue

                with get_db() as conn:
                    conn.execute("""
                        UPDATE messages
                        SET status = 'read'
                        WHERE room = %s
                        AND type = 'private'
                        AND LOWER(username) = %s
                        AND LOWER(recipient) = %s
                        AND status != 'read'
                    """, (
                        room,
                        recipient.lower(),
                        username.lower()
                    ))

                conversation = load_private_history(
                    room,
                    username,
                    recipient
                )

                for item in conversation:
                    if (
                        item["username"].lower() == recipient.lower()
                        and item["to"]
                        and item["to"].lower() == username.lower()
                        and item["status"] == "read"
                    ):
                        await update_sender_status(room, item)

                await websocket.send_json({
                    "type": "private_history",
                    "with": recipient,
                    "history": conversation
                })

            elif message_type == "private":
                recipient = str(data.get("to", "")).strip()[:30]
                message = str(data.get("text", "")).strip()

                if (
                    not recipient
                    or not message
                    or recipient.lower() == username.lower()
                ):
                    continue

                with get_db() as conn:
                    exists = conn.execute("""
                        SELECT id
                        FROM accounts
                        WHERE username_key = %s
                    """, (recipient.lower(),)).fetchone()

                if not exists:
                    await websocket.send_json({
                        "type": "system",
                        "text": "That user does not exist."
                    })
                    continue

                item = {
                    "id": uuid.uuid4().hex,
                    "type": "private",
                    "username": username,
                    "to": recipient,
                    "text": message,
                    "status": "sent"
                }

                save_message(item, room)
                await websocket.send_json(item)

                targets = find_users(room, recipient)
                delivered = False

                for target in targets:
                    delivery_item = dict(item)
                    delivery_item["status"] = "delivered"

                    try:
                        await target["websocket"].send_json(delivery_item)
                        delivered = True

                    except Exception as error:
                        print("Private delivery error:", error)

                if delivered:
                    item["status"] = "delivered"

                    with get_db() as conn:
                        conn.execute("""
                            UPDATE messages
                            SET status = 'delivered'
                            WHERE id = %s
                        """, (item["id"],))

                    await update_sender_status(room, item)

                else:
                    await websocket.send_json({
                        "type": "system",
                        "text": recipient + " is offline. Message saved."
                    })

    except WebSocketDisconnect:
        print(username, "disconnected")

    except Exception as error:
        print("WebSocket error for", username, ":", error)

    finally:
        connected_users[room] = [
            user for user in connected_users.get(room, [])
            if user["websocket"] != websocket
        ]

        if not find_users(room, username):
            await broadcast(room, {
                "type": "system",
                "text": username + " is offline."
            })

        await send_online_users(room)
