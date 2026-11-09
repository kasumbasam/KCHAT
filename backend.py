import os
import uuid
import hashlib
import secrets
import base64
import re
import json

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
            ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS about TEXT NOT NULL DEFAULT ''
        """)

        conn.execute("""
            ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS recovery_code_hash TEXT
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
            ALTER TABLE messages
            ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ
        """)

        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ
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
            CREATE INDEX IF NOT EXISTS messages_private_sender_idx
            ON messages(type, username, recipient, created_at)
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

        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_users (
                owner_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                blocked_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (owner_id, blocked_id),
                CHECK(owner_id != blocked_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_preferences (
                owner_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                peer_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                pinned BOOLEAN NOT NULL DEFAULT FALSE,
                hidden BOOLEAN NOT NULL DEFAULT FALSE,
                muted BOOLEAN NOT NULL DEFAULT FALSE,
                disappearing_seconds INTEGER NOT NULL DEFAULT 0,
                theme TEXT NOT NULL DEFAULT 'default',
                media_visibility BOOLEAN NOT NULL DEFAULT TRUE,
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (owner_id, peer_id),
                CHECK(owner_id != peer_id)
            )
        """)

        conn.execute("""
            ALTER TABLE chat_preferences
            ADD COLUMN IF NOT EXISTS muted BOOLEAN NOT NULL DEFAULT FALSE
        """)

        conn.execute("""
            ALTER TABLE chat_preferences
            ADD COLUMN IF NOT EXISTS disappearing_seconds INTEGER NOT NULL DEFAULT 0
        """)

        conn.execute("""
            ALTER TABLE chat_preferences
            ADD COLUMN IF NOT EXISTS theme TEXT NOT NULL DEFAULT 'default'
        """)

        conn.execute("""
            ALTER TABLE chat_preferences
            ADD COLUMN IF NOT EXISTS media_visibility BOOLEAN NOT NULL DEFAULT TRUE
        """)


@app.on_event("startup")
async def startup():
    init_db()


# ---------------- PHONE HELPERS ----------------

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


# ---------------- PROFILE PICTURE ----------------

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
            VALUES (%s, %s, NOW() + INTERVAL '365 days')
        """, (account_id, token_hash(token)))

    return token


def get_account_from_token(token):
    if not token:
        return None

    with get_db() as conn:
        return conn.execute("""
            SELECT accounts.id, accounts.username,
                   accounts.phone_number, accounts.profile_picture,
                   accounts.about
            FROM sessions
            JOIN accounts ON accounts.id = sessions.account_id
            WHERE sessions.token_hash = %s
            AND sessions.expires_at > NOW()
        """, (token_hash(token),)).fetchone()


def get_account_from_request(request):
    authorization = request.headers.get("Authorization", "")
    token = authorization.replace("Bearer ", "", 1)

    return get_account_from_token(token)


def users_blocked(user_id, other_id):
    with get_db() as conn:
        result = conn.execute("""
            SELECT 1
            FROM blocked_users
            WHERE (owner_id = %s AND blocked_id = %s)
               OR (owner_id = %s AND blocked_id = %s)
            LIMIT 1
        """, (
            user_id,
            other_id,
            other_id,
            user_id
        )).fetchone()

    return bool(result)


# ---------------- REGISTRATION ----------------

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
                SELECT id FROM accounts WHERE phone_key = %s
            """, (normalized_key,)).fetchone()

            if existing_phone:
                return JSONResponse({
                    "error": "That phone number is already registered."
                }, status_code=409)

            existing_username = conn.execute("""
                SELECT id FROM accounts WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if existing_username:
                return JSONResponse({
                    "error": "That username is already taken."
                }, status_code=409)

            account = conn.execute("""
                INSERT INTO accounts (
                    username, username_key, password_hash,
                    phone_number, phone_key, profile_picture
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


# ---------------- LOGIN ----------------

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
                    FROM accounts WHERE phone_key = %s
                """, (normalized_key,)).fetchone()

            if not account:
                account = conn.execute("""
                    SELECT id, username, phone_number, password_hash
                    FROM accounts WHERE username_key = %s
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


# ---------------- PASSWORD RECOVERY ----------------

@app.post("/api/account/recovery-code")
async def create_recovery_code(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        # A newly generated code replaces the previous code.
        recovery_code = secrets.token_urlsafe(12)
        recovery_hash = hashlib.sha256(recovery_code.encode("utf-8")).hexdigest()

        with get_db() as conn:
            conn.execute("""
                UPDATE accounts
                SET recovery_code_hash = %s
                WHERE id = %s
            """, (recovery_hash, account["id"]))

        return {
            "success": True,
            "recovery_code": recovery_code,
            "message": "Save this recovery code somewhere private. It will be shown only once."
        }

    except Exception as error:
        print("Recovery code generation error:", error)
        return JSONResponse({
            "error": "Could not generate a recovery code. Please try again."
        }, status_code=500)


@app.post("/api/password/reset")
async def reset_password(request: Request):
    try:
        data = await request.json()
        phone = str(data.get("phone_number", "")).strip()
        recovery_code = str(data.get("recovery_code", "")).strip()
        new_password = str(data.get("new_password", ""))

        normalized_key = phone_key(phone)

        if not normalized_key or not recovery_code or not new_password:
            return JSONResponse({
                "error": "Enter your registered phone number, recovery code and new password."
            }, status_code=400)

        if len(new_password) < 8:
            return JSONResponse({
                "error": "Your new password must contain at least 8 characters."
            }, status_code=400)

        supplied_hash = hashlib.sha256(recovery_code.encode("utf-8")).hexdigest()

        with get_db() as conn:
            account = conn.execute("""
                SELECT id, recovery_code_hash
                FROM accounts
                WHERE phone_key = %s
                FOR UPDATE
            """, (normalized_key,)).fetchone()

            if (
                not account
                or not account["recovery_code_hash"]
                or not secrets.compare_digest(
                    supplied_hash,
                    account["recovery_code_hash"]
                )
            ):
                return JSONResponse({
                    "error": "The phone number or recovery code is incorrect."
                }, status_code=401)

            new_hash = hash_password(new_password)
            conn.execute("""
                UPDATE accounts
                SET password_hash = %s,
                    recovery_code_hash = NULL
                WHERE id = %s
            """, (new_hash, account["id"]))

            # Sign out all devices after a password reset.
            conn.execute("""
                DELETE FROM sessions WHERE account_id = %s
            """, (account["id"],))

        return {
            "success": True,
            "message": "Password changed. You can now log in with your new password."
        }

    except Exception as error:
        print("Password reset error:", error)
        return JSONResponse({
            "error": "Password reset failed. Please try again."
        }, status_code=500)


# ---------------- CONTACT MANAGEMENT ----------------

@app.get("/api/contacts")
async def contacts(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT accounts.username
            FROM contacts
            JOIN accounts ON accounts.id = contacts.contact_id
            WHERE contacts.owner_id = %s
            ORDER BY accounts.username
        """, (account["id"],)).fetchall()

    return {"contacts": [row["username"] for row in rows]}


@app.post("/api/contacts")
async def add_contact(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        identifier = str(
            data.get("username") or data.get("phone_number") or data.get("identifier") or ""
        ).strip()

        if not identifier:
            return JSONResponse({
                "error": "Enter the contact's KCHAT username or registered phone number."
            }, status_code=400)

        # Accept either a username (including the displayed @username form)
        # or a registered phone number. Avoid a nullable SQL placeholder in the
        # WHERE clause so PostgreSQL can infer every parameter type reliably.
        username_identifier = identifier[1:].strip() if identifier.startswith("@") else identifier
        normalized_key = phone_key(identifier)

        with get_db() as conn:
            if normalized_key:
                target = conn.execute("""
                    SELECT id, username FROM accounts
                    WHERE username_key = %s OR phone_key = %s
                """, (username_identifier.lower(), normalized_key)).fetchone()
            else:
                target = conn.execute("""
                    SELECT id, username FROM accounts
                    WHERE username_key = %s
                """, (username_identifier.lower(),)).fetchone()

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
        return JSONResponse({"error": "Could not add contact."}, status_code=500)


@app.delete("/api/contacts/{username}")
async def remove_contact(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        target = conn.execute("""
            SELECT id FROM accounts WHERE username_key = %s
        """, (username.lower(),)).fetchone()

        if not target:
            return JSONResponse({"error": "Contact not found."}, status_code=404)

        result = conn.execute("""
            DELETE FROM contacts
            WHERE owner_id = %s AND contact_id = %s
            RETURNING id
        """, (account["id"], target["id"])).fetchone()

    if not result:
        return JSONResponse({
            "error": "That user is not in your contacts."
        }, status_code=404)

    return {"success": True, "message": "Contact removed."}


# ---------------- ACCOUNT DELETION ----------------

@app.delete("/api/account")
async def delete_account(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        password = str(data.get("password", ""))

        if not password:
            return JSONResponse({
                "error": "Enter your current password to delete your account."
            }, status_code=400)

        # Ensure every account-owned settings table exists before cleanup.
        ensure_privacy_table()

        with get_db() as conn:
            credentials = conn.execute("""
                SELECT password_hash FROM accounts WHERE id = %s
            """, (account["id"],)).fetchone()

            if not credentials or not verify_password(password, credentials["password_hash"]):
                return JSONResponse({
                    "error": "Your current password is incorrect."
                }, status_code=401)

            account_id = account["id"]
            username = account["username"]

            # Remove messages sent by this account and private messages addressed
            # to it. This also removes its public-room and group-message history.
            conn.execute("""
                DELETE FROM messages
                WHERE LOWER(username) = LOWER(%s)
                   OR LOWER(COALESCE(recipient, '')) = LOWER(%s)
            """, (username, username))

            # Explicitly remove account-owned and account-linked records.
            # The account row deletion below also removes profile fields such as
            # profile_picture, phone number, About text and recovery-code hash.
            conn.execute("DELETE FROM sessions WHERE account_id = %s", (account_id,))
            conn.execute("""
                DELETE FROM contacts
                WHERE owner_id = %s OR contact_id = %s
            """, (account_id, account_id))
            conn.execute("""
                DELETE FROM blocked_users
                WHERE owner_id = %s OR blocked_id = %s
            """, (account_id, account_id))
            conn.execute("""
                DELETE FROM chat_preferences
                WHERE owner_id = %s OR peer_id = %s
            """, (account_id, account_id))
            conn.execute("DELETE FROM user_privacy WHERE owner_id = %s", (account_id,))
            conn.execute("DELETE FROM group_members WHERE account_id = %s", (account_id,))

            # Delete groups created by this account; their memberships cascade.
            conn.execute("DELETE FROM chat_groups WHERE creator_id = %s", (account_id,))

            # Finally remove the account itself, including its profile and identity.
            conn.execute("DELETE FROM accounts WHERE id = %s", (account_id,))

        return {"success": True, "message": "Your KCHAT account has been permanently deleted."}

    except Exception as error:
        print("Account deletion error:", error)
        return JSONResponse({
            "error": "Account deletion failed. Please try again."
        }, status_code=500)


# ---------------- PROFILE AND ABOUT ----------------

@app.get("/api/profile/{username}")
async def get_profile(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        profile = conn.execute("""
            SELECT id, username, profile_picture, about
            FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

    if not profile:
        return JSONResponse({"error": "User not found."}, status_code=404)

    # A user's own profile remains visible to them.
    # Other users cannot view a profile if either person has blocked the other.
    if profile["id"] != account["id"]:
        if users_blocked(account["id"], profile["id"]):
            return JSONResponse({
                "error": "This profile is unavailable."
            }, status_code=403)

    return {
        "username": profile["username"],
        "profile_picture": profile["profile_picture"],
        "about": profile["about"] or ""
    }


@app.put("/api/profile")
async def update_profile(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()

        if not isinstance(data, dict):
            return JSONResponse({"error": "Invalid profile information."}, status_code=400)

        updates = []
        values = []

        if "profile_picture" in data:
            picture = data.get("profile_picture")

            if not validate_picture(picture):
                return JSONResponse({
                    "error": "Use a PNG, JPG or WEBP image under the size limit."
                }, status_code=400)

            updates.append("profile_picture = %s")
            values.append(picture)

        if "about" in data:
            about = data.get("about")

            if not isinstance(about, str):
                return JSONResponse({
                    "error": "About must be text."
                }, status_code=400)

            about = about.strip()

            if len(about) > 500:
                return JSONResponse({
                    "error": "About cannot exceed 500 characters."
                }, status_code=400)

            updates.append("about = %s")
            values.append(about)

        if not updates:
            return JSONResponse({
                "error": "There is nothing to update."
            }, status_code=400)

        values.append(account["id"])

        with get_db() as conn:
            conn.execute(
                "UPDATE accounts SET "
                + ", ".join(updates)
                + " WHERE id = %s",
                tuple(values)
            )

        return {
            "success": True,
            "message": "Profile updated successfully."
        }

    except Exception as error:
        print("Profile update error:", error)
        return JSONResponse({
            "error": "Could not update profile."
        }, status_code=500)


# ---------------- GROUP MANAGEMENT ----------------

@app.get("/api/groups")
async def get_groups(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                chat_groups.id,
                chat_groups.name,
                chat_groups.creator_id,
                chat_groups.created_at,
                group_members.role,
                (
                    SELECT COUNT(*) FROM group_members AS members
                    WHERE members.group_id = chat_groups.id
                ) AS member_count
            FROM chat_groups
            JOIN group_members ON group_members.group_id = chat_groups.id
            WHERE group_members.account_id = %s
            ORDER BY chat_groups.created_at DESC
        """, (account["id"],)).fetchall()

    return {
        "groups": [
            {
                "id": row["id"],
                "name": row["name"],
                "creator_id": row["creator_id"],
                "role": row["role"],
                "member_count": row["member_count"],
                "created_at": row["created_at"].isoformat()
            }
            for row in rows
        ]
    }


@app.post("/api/groups")
async def create_group(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        name = str(data.get("name", "")).strip()

        if len(name) < 2 or len(name) > 40:
            return JSONResponse({
                "error": "Group name must be between 2 and 40 characters."
            }, status_code=400)

        with get_db() as conn:
            group = conn.execute("""
                INSERT INTO chat_groups (name, name_key, creator_id)
                VALUES (%s, %s, %s)
                RETURNING id, name, creator_id, created_at
            """, (name, uuid.uuid4().hex, account["id"])).fetchone()

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
        return JSONResponse({"error": "Could not create the group."}, status_code=500)


@app.get("/api/groups/{group_id}/members")
async def get_group_members(group_id: int, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        membership = conn.execute("""
            SELECT role FROM group_members
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
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()

        if not username:
            return JSONResponse({"error": "Enter the username to add."}, status_code=400)

        with get_db() as conn:
            group = conn.execute("""
                SELECT id, creator_id FROM chat_groups WHERE id = %s
            """, (group_id,)).fetchone()

            if not group:
                return JSONResponse({"error": "Group not found."}, status_code=404)

            if group["creator_id"] != account["id"]:
                return JSONResponse({
                    "error": "Only the group creator can add members."
                }, status_code=403)

            target = conn.execute("""
                SELECT id, username FROM accounts WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not target:
                return JSONResponse({
                    "error": "No KCHAT account found with that username."
                }, status_code=404)

            existing = conn.execute("""
                SELECT account_id FROM group_members
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
        return JSONResponse({"error": "Could not add this member."}, status_code=500)


@app.delete("/api/groups/{group_id}/members/{username}")
async def remove_group_member(group_id: int, username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        group = conn.execute("""
            SELECT id, creator_id FROM chat_groups WHERE id = %s
        """, (group_id,)).fetchone()

        if not group:
            return JSONResponse({"error": "Group not found."}, status_code=404)

        if group["creator_id"] != account["id"]:
            return JSONResponse({
                "error": "Only the group creator can remove members."
            }, status_code=403)

        target = conn.execute("""
            SELECT id, username FROM accounts WHERE username_key = %s
        """, (username.lower(),)).fetchone()

        if not target:
            return JSONResponse({"error": "User not found."}, status_code=404)

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


# ---------------- INBOX ----------------

@app.get("/api/inbox")
async def get_inbox(request: Request, include_hidden: bool = False):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT *
            FROM messages
            WHERE type = 'private'
            AND (LOWER(username) = %s OR LOWER(recipient) = %s)
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
        """, (
            account["username"].lower(),
            account["username"].lower()
        )).fetchall()

        preferences = conn.execute("""
            SELECT
                accounts.username,
                chat_preferences.pinned,
                chat_preferences.hidden,
                chat_preferences.muted,
                chat_preferences.disappearing_seconds,
                chat_preferences.theme,
                chat_preferences.media_visibility
            FROM chat_preferences
            JOIN accounts ON accounts.id = chat_preferences.peer_id
            WHERE chat_preferences.owner_id = %s
        """, (account["id"],)).fetchall()

        blocked_rows = conn.execute("""
            SELECT accounts.username
            FROM blocked_users
            JOIN accounts ON accounts.id = blocked_users.blocked_id
            WHERE blocked_users.owner_id = %s
        """, (account["id"],)).fetchall()

        profiles = conn.execute("""
            SELECT id, username, profile_picture, about
            FROM accounts
        """).fetchall()

    profile_map = {
        row["username"].lower(): row
        for row in profiles
    }

    preference_map = {
        row["username"].lower(): row
        for row in preferences
    }

    blocked_names = {
        row["username"].lower()
        for row in blocked_rows
    }

    conversations = {}

    for row in rows:
        sender = row["username"]
        recipient = row["recipient"]

        if sender.lower() == account["username"].lower():
            peer = recipient
        else:
            peer = sender

        if not peer:
            continue

        key = peer.lower()

        if key not in conversations:
            pref = preference_map.get(key, {})
            peer_profile = profile_map.get(key, {})

            restricted = False

            if peer_profile:
                restricted = users_blocked(account["id"], peer_profile["id"])

            conversations[key] = {
                "username": peer,
                "profile_picture": (
                    None if restricted else peer_profile.get("profile_picture")
                ),
                "about": (
                    "" if restricted else peer_profile.get("about", "")
                ),
                "last_message": row["text"],
                "last_message_id": row["id"],
                "last_message_time": (
                    row["created_at"].isoformat()
                    if row["created_at"] else None
                ),
                "last_message_sender": sender,
                "last_message_status": row["status"],
                "unread_count": 0,
                "pinned": pref.get("pinned", False),
                "hidden": pref.get("hidden", False),
                "muted": pref.get("muted", False),
                "disappearing_seconds": pref.get("disappearing_seconds", 0),
                "theme": pref.get("theme", "default"),
                "media_visibility": pref.get("media_visibility", True),
                "blocked": key in blocked_names,
                "restricted": restricted
            }

        if (
            recipient
            and recipient.lower() == account["username"].lower()
            and sender.lower() != account["username"].lower()
            and row["status"] != "read"
        ):
            conversations[key]["unread_count"] += 1

    inbox = list(conversations.values())

    if not include_hidden:
        inbox = [item for item in inbox if not item["hidden"]]

    inbox.sort(
        key=lambda item: (
            item["pinned"],
            item["last_message_time"] or ""
        ),
        reverse=True
    )

    return {"inbox": inbox, "total": len(inbox)}


# ---------------- CHAT SETTINGS ----------------

@app.put("/api/chats/{username}/settings")
async def update_chat_settings(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()

        with get_db() as conn:
            peer = conn.execute("""
                SELECT id, username FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not peer:
                return JSONResponse({"error": "User not found."}, status_code=404)

            if peer["id"] == account["id"]:
                return JSONResponse({
                    "error": "You cannot change chat settings for yourself."
                }, status_code=400)

            if users_blocked(account["id"], peer["id"]):
                return JSONResponse({
                    "error": "This conversation is unavailable."
                }, status_code=403)

            current = conn.execute("""
                SELECT *
                FROM chat_preferences
                WHERE owner_id = %s AND peer_id = %s
            """, (account["id"], peer["id"])).fetchone()

            settings = {
                "pinned": current["pinned"] if current else False,
                "hidden": current["hidden"] if current else False,
                "muted": current["muted"] if current else False,
                "disappearing_seconds": (
                    current["disappearing_seconds"] if current else 0
                ),
                "theme": current["theme"] if current else "default",
                "media_visibility": (
                    current["media_visibility"] if current else True
                )
            }

            boolean_fields = [
                "pinned", "hidden", "muted", "media_visibility"
            ]

            for field in boolean_fields:
                if field in data:
                    if not isinstance(data[field], bool):
                        return JSONResponse({
                            "error": field + " must be true or false."
                        }, status_code=400)
                    settings[field] = data[field]

            if "disappearing_seconds" in data:
                seconds = data["disappearing_seconds"]

                if (
                    not isinstance(seconds, int)
                    or seconds not in (0, 86400, 604800, 7776000)
                ):
                    return JSONResponse({
                        "error": "Choose off, 24 hours, 7 days or 90 days."
                    }, status_code=400)

                settings["disappearing_seconds"] = seconds

            if "theme" in data:
                theme = str(data["theme"]).lower()

                if theme not in (
                    "default", "dark", "light", "blue", "green"
                ):
                    return JSONResponse({
                        "error": "Invalid chat theme."
                    }, status_code=400)

                settings["theme"] = theme

            # Save the current user's settings.
            conn.execute("""
                INSERT INTO chat_preferences (
                    owner_id, peer_id, pinned, hidden, muted,
                    disappearing_seconds, theme, media_visibility, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (owner_id, peer_id)
                DO UPDATE SET
                    pinned = EXCLUDED.pinned,
                    hidden = EXCLUDED.hidden,
                    muted = EXCLUDED.muted,
                    disappearing_seconds = EXCLUDED.disappearing_seconds,
                    theme = EXCLUDED.theme,
                    media_visibility = EXCLUDED.media_visibility,
                    updated_at = NOW()
            """, (
                account["id"],
                peer["id"],
                settings["pinned"],
                settings["hidden"],
                settings["muted"],
                settings["disappearing_seconds"],
                settings["theme"],
                settings["media_visibility"]
            ))

            # Disappearing-message duration is shared by both people.
            if "disappearing_seconds" in data:
                conn.execute("""
                    INSERT INTO chat_preferences (
                        owner_id, peer_id, disappearing_seconds
                    )
                    VALUES (%s, %s, %s)
                    ON CONFLICT (owner_id, peer_id)
                    DO UPDATE SET
                        disappearing_seconds = EXCLUDED.disappearing_seconds,
                        updated_at = NOW()
                """, (
                    peer["id"],
                    account["id"],
                    settings["disappearing_seconds"]
                ))

        return {
            "success": True,
            "username": peer["username"],
            **settings
        }

    except Exception as error:
        print("Chat settings error:", error)
        return JSONResponse({
            "error": "Could not update chat settings."
        }, status_code=500)


# ---------------- MESSAGE SEARCH ----------------

@app.get("/api/messages/search")
async def search_messages(
    request: Request,
    q: str = "",
    with_user: str = ""
):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    query = q.strip()

    if len(query) < 2:
        return JSONResponse({
            "error": "Enter at least 2 characters to search.",
            "results": []
        }, status_code=400)

    query = query[:200]

    parameters = [
        account["username"].lower(),
        account["username"].lower(),
        "%" + query + "%"
    ]

    sql = """
        SELECT *
        FROM messages
        WHERE type = 'private'
        AND (LOWER(username) = %s OR LOWER(recipient) = %s)
        AND text ILIKE %s
        AND (expires_at IS NULL OR expires_at > NOW())
    """

    if with_user.strip():
        sql += """
            AND (LOWER(username) = %s OR LOWER(recipient) = %s)
        """
        parameters.extend([
            with_user.strip().lower(),
            with_user.strip().lower()
        ])

    sql += " ORDER BY created_at DESC LIMIT 100"

    with get_db() as conn:
        rows = conn.execute(sql, tuple(parameters)).fetchall()

    results = []

    for row in rows:
        peer = (
            row["recipient"]
            if row["username"].lower() == account["username"].lower()
            else row["username"]
        )

        results.append({
            "id": row["id"],
            "username": row["username"],
            "to": row["recipient"],
            "with": peer,
            "text": row["text"],
            "status": row["status"],
            "created_at": (
                row["created_at"].isoformat()
                if row["created_at"] else None
            )
        })

    return {
        "success": True,
        "query": query,
        "results": results,
        "total": len(results)
    }




# ---------------- PRIVATE MESSAGE HISTORY AND DELIVERY ----------------

@app.get("/api/messages/{username}")
async def get_private_messages(username: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    peer_name = username.strip()[:30]
    if not peer_name or peer_name.lower() == account["username"].lower():
        return JSONResponse({"error": "Choose a valid conversation."}, status_code=400)

    with get_db() as conn:
        peer = conn.execute("""
            SELECT id, username FROM accounts WHERE username_key = %s
        """, (peer_name.lower(),)).fetchone()
        if not peer:
            return JSONResponse({"error": "User not found."}, status_code=404)
        if users_blocked(account["id"], peer["id"]):
            return JSONResponse({"error": "This conversation is unavailable."}, status_code=403)

        rows = conn.execute("""
            SELECT * FROM messages
            WHERE type = 'private'
            AND (
                (LOWER(username) = %s AND LOWER(recipient) = %s)
                OR
                (LOWER(username) = %s AND LOWER(recipient) = %s)
            )
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at ASC
        """, (
            account["username"].lower(), peer["username"].lower(),
            peer["username"].lower(), account["username"].lower()
        )).fetchall()

        unread = []
        if get_privacy_settings(account["id"]).get("read_receipts", True):
            unread = conn.execute("""
                UPDATE messages SET status = 'read'
                WHERE type = 'private'
                AND LOWER(username) = %s
                AND LOWER(recipient) = %s
                AND status != 'read'
                AND (expires_at IS NULL OR expires_at > NOW())
                RETURNING id, username, room
            """, (peer["username"].lower(), account["username"].lower())).fetchall()

    for row in unread:
        await update_sender_status(row["room"], {
            "id": row["id"], "username": row["username"], "status": "read"
        })

    peer_privacy = get_privacy_settings(peer["id"])
    visible_messages = []
    for row in rows:
        item = message_from_row(row)
        if row["username"].lower() == account["username"].lower():
            if not peer_privacy.get("delivery_receipts", True):
                item["status"] = "sent"
            elif (
                item.get("status") == "read"
                and not peer_privacy.get("read_receipts", True)
            ):
                item["status"] = "delivered"

        if item.get("revoked"):
            if row["username"].lower() != account["username"].lower():
                my_privacy = get_privacy_settings(account["id"])
                item["revoked_retained"] = my_privacy.get("anti_revoke", True)
                if not item["revoked_retained"]:
                    item["text"] = "This message was deleted"
            else:
                item["revoked_retained"] = True

        visible_messages.append(item)

    return {"messages": visible_messages, "with": peer["username"]}


@app.post("/api/messages/{message_id}/revoke")
async def revoke_private_message(message_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        message = conn.execute("""
            SELECT id, type, username, recipient, revoked_at
            FROM messages
            WHERE id = %s
            FOR UPDATE
        """, (message_id,)).fetchone()

        if not message or message["type"] != "private":
            return JSONResponse({"error": "Message not found."}, status_code=404)

        if message["username"].lower() != account["username"].lower():
            return JSONResponse({
                "error": "You can only delete messages you sent."
            }, status_code=403)

        if message["revoked_at"]:
            return JSONResponse({
                "error": "This message has already been deleted for everyone."
            }, status_code=409)

        conn.execute("""
            UPDATE messages
            SET revoked_at = NOW()
            WHERE id = %s
        """, (message_id,))

        recipient = conn.execute("""
            SELECT id FROM accounts WHERE username_key = %s
        """, (message["recipient"].lower(),)).fetchone()

    recipient_privacy = (
        get_privacy_settings(recipient["id"])
        if recipient else {}
    )
    retained = recipient_privacy.get("anti_revoke", True)
    event = {
        "type": "message_revoked",
        "id": message_id,
        "username": account["username"],
        "retained": retained
    }

    for websocket in connected_sockets_for(message["recipient"]):
        try:
            await websocket.send_json(event)
        except Exception as error:
            print("Message revoke notification error:", error)

    return {
        "success": True,
        "message": "Message deleted for everyone.",
        "retained_for_recipient": retained
    }


@app.post("/api/messages")
async def send_private_message(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        recipient_name = str(data.get("recipient", data.get("to", ""))).strip()[:30]
        message_text = str(data.get("text", "")).strip()
        if not recipient_name or not message_text:
            return JSONResponse({"error": "Choose a recipient and enter a message."}, status_code=400)
        if recipient_name.lower() == account["username"].lower():
            return JSONResponse({"error": "You cannot message yourself."}, status_code=400)

        with get_db() as conn:
            target = conn.execute("""
                SELECT id, username FROM accounts WHERE username_key = %s
            """, (recipient_name.lower(),)).fetchone()
        if not target:
            return JSONResponse({"error": "That KCHAT user does not exist."}, status_code=404)
        if users_blocked(account["id"], target["id"]):
            return JSONResponse({"error": "Message not sent. This conversation is blocked."}, status_code=403)

        recipient = target["username"]
        private_room = "private:" + ":".join(private_pair(account["username"], recipient))
        item = {
            "id": uuid.uuid4().hex,
            "type": "private",
            "username": account["username"],
            "to": recipient,
            "text": message_text[:10000],
            "status": "sent"
        }
        item = save_message(item, private_room)
        delivered = False

        for target_socket in connected_sockets_for(recipient):
            try:
                delivery_item = dict(item)
                delivery_item["status"] = "delivered"
                await target_socket.send_json(delivery_item)
                delivered = True
            except Exception as error:
                print("Private HTTP delivery error:", error)

        if delivered:
            item["status"] = "delivered"
            with get_db() as conn:
                conn.execute("UPDATE messages SET status = 'delivered' WHERE id = %s", (item["id"],))
            await update_sender_status(private_room, item)

        response_item = dict(item)
        recipient_privacy = get_privacy_settings(target["id"])
        if (
            response_item.get("status") == "delivered"
            and not recipient_privacy.get("delivery_receipts", True)
        ):
            response_item["status"] = "sent"
        elif (
            response_item.get("status") == "read"
            and not recipient_privacy.get("read_receipts", True)
        ):
            response_item["status"] = (
                "delivered"
                if recipient_privacy.get("delivery_receipts", True)
                else "sent"
            )

        return {
            "success": True,
            "message": response_item,
            "delivery": response_item["status"]
        }
    except Exception as error:
        print("Private message send error:", error)
        return JSONResponse({"error": "The message could not be sent. Please try again."}, status_code=500)


# ---------------- MARK ALL AS READ ----------------

@app.post("/api/messages/read-all")
async def mark_all_messages_read(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    if not get_privacy_settings(account["id"]).get("read_receipts", True):
        return {
            "success": True,
            "marked_read": 0,
            "message": "Read receipts are disabled."
        }

    with get_db() as conn:
        rows = conn.execute("""
            UPDATE messages
            SET status = 'read'
            WHERE type = 'private'
            AND LOWER(recipient) = %s
            AND status != 'read'
            AND (expires_at IS NULL OR expires_at > NOW())
            RETURNING id, username, room
        """, (account["username"].lower(),)).fetchall()

    for row in rows:
        await update_sender_status(row["room"], {
            "id": row["id"],
            "username": row["username"],
            "status": "read"
        })

    return {
        "success": True,
        "marked_read": len(rows),
        "message": "All private messages marked as read."
    }


# ---------------- BLOCKED CONTACTS ----------------

@app.get("/api/blocks")
async def get_blocked_users(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT accounts.username, blocked_users.created_at
            FROM blocked_users
            JOIN accounts ON accounts.id = blocked_users.blocked_id
            WHERE blocked_users.owner_id = %s
            ORDER BY blocked_users.created_at DESC
        """, (account["id"],)).fetchall()

    return {
        "blocked": [
            {
                "username": row["username"],
                "created_at": (
                    row["created_at"].isoformat()
                    if row["created_at"] else None
                )
            }
            for row in rows
        ]
    }


@app.post("/api/blocks")
async def block_user(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()

        if not username:
            return JSONResponse({
                "error": "Enter a username to block."
            }, status_code=400)

        with get_db() as conn:
            target = conn.execute("""
                SELECT id, username FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not target:
                return JSONResponse({"error": "User not found."}, status_code=404)

            if target["id"] == account["id"]:
                return JSONResponse({
                    "error": "You cannot block yourself."
                }, status_code=400)

            conn.execute("""
                INSERT INTO blocked_users (owner_id, blocked_id)
                VALUES (%s, %s)
                ON CONFLICT (owner_id, blocked_id) DO NOTHING
            """, (account["id"], target["id"]))

        return {
            "success": True,
            "username": target["username"],
            "message": "Contact blocked."
        }

    except Exception as error:
        print("Block user error:", error)
        return JSONResponse({
            "error": "Could not block this user."
        }, status_code=500)


@app.delete("/api/blocks/{username}")
async def unblock_user(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        target = conn.execute("""
            SELECT id, username FROM accounts
            WHERE username_key = %s
        """, (username.lower(),)).fetchone()

        if not target:
            return JSONResponse({"error": "User not found."}, status_code=404)

        result = conn.execute("""
            DELETE FROM blocked_users
            WHERE owner_id = %s AND blocked_id = %s
            RETURNING blocked_id
        """, (account["id"], target["id"])).fetchone()

    if not result:
        return JSONResponse({
            "error": "That user is not blocked."
        }, status_code=404)

    return {
        "success": True,
        "message": target["username"] + " has been unblocked."
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
    return sorted([user1.lower(), user2.lower()])


def save_message(item, room):
    expires_at = None

    if item["type"] == "private" and item.get("to"):
        with get_db() as conn:
            setting = conn.execute("""
                SELECT disappearing_seconds
                FROM chat_preferences
                WHERE owner_id = (
                    SELECT id FROM accounts WHERE username_key = %s
                )
                AND peer_id = (
                    SELECT id FROM accounts WHERE username_key = %s
                )
            """, (
                item["username"].lower(),
                item["to"].lower()
            )).fetchone()

            seconds = setting["disappearing_seconds"] if setting else 0

            if seconds:
                expires_at = seconds

    with get_db() as conn:
        if expires_at:
            row = conn.execute("""
                INSERT INTO messages (
                    id, type, room, username, recipient, text, status, expires_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    NOW() + (%s * INTERVAL '1 second')
                )
                RETURNING created_at, expires_at
            """, (
                item["id"],
                item["type"],
                room,
                item["username"],
                item.get("to"),
                item["text"],
                item.get("status"),
                expires_at
            )).fetchone()
        else:
            row = conn.execute("""
                INSERT INTO messages (
                    id, type, room, username, recipient, text, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING created_at, expires_at
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
    item["expires_at"] = (
        row["expires_at"].isoformat()
        if row["expires_at"] else None
    )

    return item


def message_from_row(row):
    return {
        "id": row["id"],
        "type": row["type"],
        "username": row["username"],
        "to": row["recipient"],
        "text": row["text"],
        "status": row["status"],
        "revoked": bool(row.get("revoked_at")),
        "revoked_at": (
            row["revoked_at"].isoformat()
            if row.get("revoked_at") else None
        ),
        "created_at": (
            row["created_at"].isoformat()
            if row["created_at"] else None
        ),
        "expires_at": (
            row["expires_at"].isoformat()
            if row.get("expires_at") else None
        )
    }


def load_group_history(room):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT *
            FROM messages
            WHERE room = %s AND type = 'chat'
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at ASC
        """, (room,)).fetchall()

    return [message_from_row(row) for row in rows]


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
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at ASC
        """, (
            room,
            first,
            second,
            second,
            first
        )).fetchall()

    return [message_from_row(row) for row in rows]


def is_user_online(username):
    return bool(connected_sockets_for(username))


async def notify_contact_presence(username, online):
    """Notify only accounts that have this user in their KCHAT contacts."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT DISTINCT owner.id, owner.username
            FROM contacts
            JOIN accounts AS owner ON owner.id = contacts.owner_id
            JOIN accounts AS contact ON contact.id = contacts.contact_id
            WHERE LOWER(contact.username_key) = LOWER(%s)
        """, (username,)).fetchall()

    with get_db() as conn:
        owner = conn.execute(
            "SELECT id FROM accounts WHERE username_key = %s",
            (username.lower(),)
        ).fetchone()

    for row in rows:
        visible_online = bool(
            online and owner and can_view_presence(owner["id"], row["id"])
        )
        event = {
            "type": "presence",
            "username": username,
            "online": visible_online
        }
        for websocket in connected_sockets_for(row["username"]):
            try:
                await websocket.send_json(event)
            except Exception as error:
                print("Presence notification error:", error)


async def send_contact_presence(account, websocket):
    """Send the signed-in user the current presence of their saved contacts."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT contact.id, contact.username
            FROM contacts
            JOIN accounts AS contact ON contact.id = contacts.contact_id
            WHERE contacts.owner_id = %s
        """, (account["id"],)).fetchall()

    for row in rows:
        username = row["username"]
        if not can_view_presence(row["id"], account["id"]):
            continue
        try:
            await websocket.send_json({
                "type": "presence",
                "username": username,
                "online": is_user_online(username)
            })
        except Exception as error:
            print("Initial presence error:", error)
            break


def connected_sockets_for(username):
    matches = []
    for room_users in list(connected_users.values()):
        for user in list(room_users):
            if (
                user["username"].lower() == username.lower()
                and user["websocket"].client_state == WebSocketState.CONNECTED
            ):
                matches.append(user["websocket"])
    return matches


async def update_sender_status(room, item):
    with get_db() as conn:
        message = conn.execute(
            "SELECT recipient FROM messages WHERE id = %s",
            (item["id"],)
        ).fetchone()
        recipient_name = message["recipient"] if message else None
        recipient = None
        if recipient_name:
            recipient = conn.execute(
                "SELECT id FROM accounts WHERE username_key = %s",
                (recipient_name.lower(),)
            ).fetchone()

    if recipient:
        preferences = get_privacy_settings(recipient["id"])
        if item.get("status") == "read" and not preferences.get("read_receipts", True):
            return
        if item.get("status") == "delivered" and not preferences.get("delivery_receipts", True):
            return

    for websocket in connected_sockets_for(item["username"]):
        try:
            await websocket.send_json({
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
            WHERE type = 'private'
            AND LOWER(recipient) = %s
            AND status = 'sent'
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at ASC
        """, (username.lower(),)).fetchall()

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
            """, (group_id, account["id"])).fetchone()

        if not membership:
            await websocket.close(code=4403)
            return

    connected_users.setdefault(room, [])

    was_online = bool(find_users(room, username))

    connected_users[room].append({
        "username": username,
        "websocket": websocket
    })

    # Presence is account-wide, not limited to the currently joined room.
    await send_contact_presence(account, websocket)
    await notify_contact_presence(username, True)

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
                    target = conn.execute("""
                        SELECT id, username FROM accounts
                        WHERE username_key = %s
                    """, (recipient.lower(),)).fetchone()

                if not target:
                    await websocket.send_json({
                        "type": "system",
                        "text": "That user does not exist."
                    })
                    continue

                if users_blocked(account["id"], target["id"]):
                    await websocket.send_json({
                        "type": "system",
                        "text": "This conversation is unavailable because one of the users has blocked the other."
                    })
                    continue

                recipient = target["username"]

                if get_privacy_settings(account["id"]).get("read_receipts", True):
                    with get_db() as conn:
                        conn.execute("""
                            UPDATE messages
                            SET status = 'read'
                            WHERE room = %s
                            AND type = 'private'
                            AND LOWER(username) = %s
                            AND LOWER(recipient) = %s
                            AND status != 'read'
                            AND (expires_at IS NULL OR expires_at > NOW())
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
                    target_account = conn.execute("""
                        SELECT id, username FROM accounts
                        WHERE username_key = %s
                    """, (recipient.lower(),)).fetchone()

                if not target_account:
                    await websocket.send_json({
                        "type": "system",
                        "text": "That user does not exist."
                    })
                    continue

                if users_blocked(account["id"], target_account["id"]):
                    await websocket.send_json({
                        "type": "system",
                        "text": "Message not sent. This conversation is blocked."
                    })
                    continue

                recipient = target_account["username"]

                item = {
                    "id": uuid.uuid4().hex,
                    "type": "private",
                    "username": username,
                    "to": recipient,
                    "text": message,
                    "status": "sent"
                }

                private_room = "private:" + ":".join(private_pair(username, recipient))
                save_message(item, private_room)
                await websocket.send_json(item)

                targets = connected_sockets_for(recipient)
                delivered = False

                for target in targets:
                    delivery_item = dict(item)
                    delivery_item["status"] = "delivered"

                    try:
                        await target.send_json(delivery_item)
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

        # Mark offline only after the user's last active socket has closed.
        if not is_user_online(username):
            await notify_contact_presence(username, False)

        if not find_users(room, username):
            await broadcast(room, {
                "type": "system",
                "text": username + " is offline."
            })

        await send_online_users(room)
        # ============================================================
# KCHAT PRIVACY AND SECURITY SETTINGS
# ============================================================

DEFAULT_PRIVACY_SETTINGS = {
    "last_seen": "everyone",
    "online": "everyone",
    "profile_photo": "everyone",
    "about_visibility": "everyone",
    "read_receipts": True,
    "delivery_receipts": True,
    "anti_revoke": True,
    "group_add": "everyone",
    "group_last_seen": "same_as_last_seen",
    "status_audience": "all_contacts",
    "status_excluded": [],
    "status_allowed": [],
    "allow_status_sharing": True,
    "default_message_timer": 0,
    "silence_unknown_calls": False,
    "app_lock": False
}

PRIVACY_VISIBILITY_OPTIONS = {
    "last_seen": [
        "everyone", "my_contacts",
        "my_contacts_except", "nobody"
    ],
    "online": [
        "everyone", "same_as_last_seen", "nobody"
    ],
    "profile_photo": [
        "everyone", "my_contacts",
        "my_contacts_except", "nobody"
    ],
    "about_visibility": [
        "everyone", "my_contacts",
        "my_contacts_except", "nobody"
    ],
    "group_add": [
        "everyone", "my_contacts",
        "my_contacts_except", "nobody"
    ],
    "group_last_seen": [
        "everyone", "nobody", "same_as_last_seen",
        "my_contacts"
    ],
    "status_audience": [
        "all_contacts",
        "my_contacts_except",
        "only_share_with"
    ]
}

ALLOWED_MESSAGE_TIMERS = [0, 86400, 604800, 7776000]


def ensure_privacy_table():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_privacy (
                owner_id BIGINT PRIMARY KEY
                    REFERENCES accounts(id) ON DELETE CASCADE,
                settings TEXT NOT NULL DEFAULT '{}',
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)


def get_privacy_settings(owner_id):
    ensure_privacy_table()

    with get_db() as conn:
        row = conn.execute("""
            SELECT settings
            FROM user_privacy
            WHERE owner_id = %s
        """, (owner_id,)).fetchone()

    settings = dict(DEFAULT_PRIVACY_SETTINGS)

    if row:
        try:
            saved = json.loads(row["settings"])
            if isinstance(saved, dict):
                settings.update(saved)
        except Exception:
            pass

    return settings


def can_view_presence(owner_id, viewer_id):
    """Check whether this viewer may see the owner's online state."""
    settings = get_privacy_settings(owner_id)
    rule = settings.get("online", "everyone")
    if rule == "nobody":
        return False
    if rule == "everyone":
        return True
    last_seen = settings.get("last_seen", "everyone")
    if last_seen == "nobody":
        return False
    if last_seen == "everyone":
        return True
    with get_db() as conn:
        contact = conn.execute("""
            SELECT 1 FROM contacts
            WHERE owner_id = %s AND contact_id = %s
            LIMIT 1
        """, (owner_id, viewer_id)).fetchone()
    return bool(contact)


@app.get("/api/privacy")
async def get_privacy(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    return {
        "success": True,
        "settings": get_privacy_settings(account["id"])
    }


@app.put("/api/privacy")
async def update_privacy(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    try:
        data = await request.json()

        if not isinstance(data, dict):
            return JSONResponse(
                {"error": "Invalid privacy settings."},
                status_code=400
            )

        settings = get_privacy_settings(account["id"])

        for key, allowed in PRIVACY_VISIBILITY_OPTIONS.items():
            if key in data:
                value = data[key]

                if value not in allowed:
                    return JSONResponse({
                        "error": "Invalid value for " + key
                    }, status_code=400)

                settings[key] = value

        boolean_fields = [
            "read_receipts",
            "delivery_receipts",
            "anti_revoke",
            "allow_status_sharing",
            "silence_unknown_calls",
            "app_lock"
        ]

        for key in boolean_fields:
            if key in data:
                if not isinstance(data[key], bool):
                    return JSONResponse({
                        "error": key + " must be true or false."
                    }, status_code=400)

                settings[key] = data[key]

        if "default_message_timer" in data:
            timer = data["default_message_timer"]

            if (
                isinstance(timer, bool)
                or timer not in ALLOWED_MESSAGE_TIMERS
            ):
                return JSONResponse({
                    "error": "Invalid disappearing message timer."
                }, status_code=400)

            settings["default_message_timer"] = timer

        for key in ["status_excluded", "status_allowed"]:
            if key in data:
                value = data[key]

                if (
                    not isinstance(value, list)
                    or len(value) > 500
                    or not all(
                        isinstance(name, str)
                        and 1 <= len(name.strip()) <= 30
                        for name in value
                    )
                ):
                    return JSONResponse({
                        "error": "Invalid status audience list."
                    }, status_code=400)

                settings[key] = list(dict.fromkeys(
                    name.strip() for name in value
                ))

        ensure_privacy_table()

        with get_db() as conn:
            conn.execute("""
                INSERT INTO user_privacy (
                    owner_id, settings, updated_at
                )
                VALUES (%s, %s, NOW())
                ON CONFLICT (owner_id)
                DO UPDATE SET
                    settings = EXCLUDED.settings,
                    updated_at = NOW()
            """, (
                account["id"],
                json.dumps(settings)
            ))

        await notify_contact_presence(
            account["username"],
            is_user_online(account["username"])
        )

        return {
            "success": True,
            "message": "Privacy settings saved.",
            "settings": settings
        }

    except Exception as error:
        print("Privacy settings error:", error)

        return JSONResponse({
            "error": "Could not save privacy settings."
        }, status_code=500)


# ============================================================
# KCHAT INDIVIDUAL CHAT PRIVACY
# ============================================================

@app.put("/api/chats/{username}/privacy")
async def update_chat_privacy(username: str, request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse(
            {"error": "Please log in again."},
            status_code=401
        )

    try:
        data = await request.json()

        if not isinstance(data, dict):
            return JSONResponse(
                {"error": "Invalid chat settings."},
                status_code=400
            )

        allowed_fields = {
            "chat_locked": bool,
            "last_seen_visibility": str
        }

        for key in data:
            if key not in allowed_fields:
                return JSONResponse({
                    "error": "Unsupported chat privacy setting."
                }, status_code=400)

        if (
            "chat_locked" in data
            and not isinstance(data["chat_locked"], bool)
        ):
            return JSONResponse({
                "error": "Chat lock must be true or false."
            }, status_code=400)

        if "last_seen_visibility" in data:
            if data["last_seen_visibility"] not in [
                "normal", "hidden"
            ]:
                return JSONResponse({
                    "error": "Invalid last seen visibility."
                }, status_code=400)

        with get_db() as conn:
            target = conn.execute("""
                SELECT id, username
                FROM accounts
                WHERE username_key = %s
            """, (username.lower(),)).fetchone()

            if not target:
                return JSONResponse({
                    "error": "Contact not found."
                }, status_code=404)

            if target["id"] == account["id"]:
                return JSONResponse({
                    "error": "You cannot change privacy for yourself."
                }, status_code=400)

            if "chat_locked" in data:
                conn.execute("""
                    UPDATE chat_preferences
                    SET updated_at = NOW()
                    WHERE owner_id = %s AND peer_id = %s
                """, (account["id"], target["id"]))

                conn.execute("""
                    INSERT INTO chat_preferences (
                        owner_id, peer_id
                    )
                    VALUES (%s, %s)
                    ON CONFLICT (owner_id, peer_id)
                    DO NOTHING
                """, (account["id"], target["id"]))

                conn.execute("""
                    ALTER TABLE chat_preferences
                    ADD COLUMN IF NOT EXISTS chat_locked
                    BOOLEAN NOT NULL DEFAULT FALSE
                """)

                conn.execute("""
                    UPDATE chat_preferences
                    SET chat_locked = %s, updated_at = NOW()
                    WHERE owner_id = %s AND peer_id = %s
                """, (
                    data["chat_locked"],
                    account["id"],
                    target["id"]
                ))

            if "last_seen_visibility" in data:
                conn.execute("""
                    ALTER TABLE chat_preferences
                    ADD COLUMN IF NOT EXISTS last_seen_visibility
                    TEXT NOT NULL DEFAULT 'normal'
                """)

                conn.execute("""
                    INSERT INTO chat_preferences (
                        owner_id, peer_id, last_seen_visibility
                    )
                    VALUES (%s, %s, %s)
                    ON CONFLICT (owner_id, peer_id)
                    DO UPDATE SET
                        last_seen_visibility = EXCLUDED.last_seen_visibility,
                        updated_at = NOW()
                """, (
                    account["id"],
                    target["id"],
                    data["last_seen_visibility"]
                ))

        return {
            "success": True,
            "message": "Individual chat privacy saved."
        }

    except Exception as error:
        print("Chat privacy error:", error)

        return JSONResponse({
            "error": "Could not update chat privacy."
        }, status_code=500)
