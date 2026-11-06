
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
            CREATE TABLE IF NOT EXISTS sessions (
                id BIGSERIAL PRIMARY KEY,
                account_id BIGINT REFERENCES accounts(id)
                    ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
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
            CREATE INDEX IF NOT EXISTS messages_room_idx
            ON messages(room, created_at)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS messages_recipient_idx
            ON messages(room, recipient, status)
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


@app.get("/api/contacts")
async def contacts(request: Request):
    authorization = request.headers.get("Authorization", "")
    token = authorization.replace("Bearer ", "", 1)
    account = get_account_from_token(token)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    with get_db() as conn:
        rows = conn.execute("""
            SELECT username FROM accounts
            WHERE id != %s
            ORDER BY username
        """, (account["id"],)).fetchall()

    return {"contacts": [row["username"] for row in rows]}


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
    return sorted([user1.lower(), user2.lower()])


def save_message(item, room):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO messages
                (id, type, room, username, recipient, text, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            item["id"],
            item["type"],
            room,
            item["username"],
            item.get("to"),
            item["text"],
            item.get("status")
        ))


def message_from_row(row):
    return {
        "id": row["id"],
        "type": row["type"],
        "username": row["username"],
        "to": row["recipient"],
        "text": row["text"],
        "status": row["status"]
    }


def load_group_history(room):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM messages
            WHERE room = %s AND type = 'chat'
            ORDER BY created_at ASC
            LIMIT 200
        """, (room,)).fetchall()

    return [
        {
            "type": "chat",
            "username": row["username"],
            "text": row["text"]
        }
        for row in rows
    ]


def load_private_history(room, user1, user2):
    first, second = private_pair(user1, user2)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM messages
            WHERE room = %s
            AND type = 'private'
            AND (
                (LOWER(username) = %s AND LOWER(recipient) = %s)
                OR
                (LOWER(username) = %s AND LOWER(recipient) = %s)
            )
            ORDER BY created_at ASC
            LIMIT 200
        """, (room, first, second, second, first)).fetchall()

    return [message_from_row(row) for row in rows]


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
            SELECT * FROM messages
            WHERE room = %s
            AND type = 'private'
            AND LOWER(recipient) = %s
            AND status = 'sent'
            ORDER BY created_at ASC
        """, (room, username.lower())).fetchall()

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

    connected_users.setdefault(room, [])

    connected_users[room].append({
        "username": username,
        "websocket": websocket
    })

    await websocket.send_json({
        "type": "welcome",
        "history": load_group_history(room),
        "users": list(dict.fromkeys(
            user["username"] for user in connected_users[room]
        ))
    })

    await broadcast(room, {
        "type": "system",
        "text": username + " joined the room."
    })

    await send_online_users(room)

    try:
        await deliver_pending_messages(room, username, websocket)

        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")

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
                        room, recipient.lower(), username.lower()
                    ))

                conversation = load_private_history(
                    room, username, recipient
                )

                for item in conversation:
                    if (
                        item["username"].lower() == recipient.lower()
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

                if not recipient or not message:
                    continue

                if recipient.lower() == username.lower():
                    continue

                with get_db() as conn:
                    exists = conn.execute("""
                        SELECT id FROM accounts
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

        await broadcast(room, {
            "type": "system",
            "text": username + " left the room."
        })

        await send_online_users(room)
