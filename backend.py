import os
import uuid
import hashlib
import secrets
import base64
import re
import json
import asyncio
import urllib.request
import urllib.error

from openai import AsyncOpenAI

import psycopg
from psycopg.rows import dict_row

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, JSONResponse, Response
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
            ALTER TABLE messages
            ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS message_hidden (
                owner_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                message_id TEXT REFERENCES messages(id) ON DELETE CASCADE,
                hidden_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (owner_id, message_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS pinned_messages (
                owner_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
                message_id TEXT REFERENCES messages(id) ON DELETE CASCADE,
                pinned_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (owner_id, message_id)
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



# ---------------- FREE IMAGE GENERATION (CLOUDFLARE) ----------------

def _cloudflare_generate_image(prompt):
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not account_id or not api_token:
        return None

    model = os.environ.get(
        "CLOUDFLARE_IMAGE_MODEL",
        "@cf/black-forest-labs/flux-1-schnell"
    ).strip()
    endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        + account_id + "/ai/run/" + model
    )
    payload = json.dumps({"prompt": prompt[:2048]}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Authorization": "Bearer " + api_token,
            "Content-Type": "application/json"
        }
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        result = json.loads(response.read().decode("utf-8"))

    image_data = (result.get("result") or {}).get("image")
    if not result.get("success") or not image_data:
        raise RuntimeError("Cloudflare did not return a generated image.")
    return "data:image/jpeg;base64," + image_data


async def cloudflare_generate_images(prompt, count=1):
    count = max(1, min(4, int(count)))
    images = []
    for _ in range(count):
        image_data = await asyncio.to_thread(_cloudflare_generate_image, prompt)
        if image_data:
            images.append(image_data)
    return images


# ---------------- KCHAT AI (OPENAI) ----------------

@app.post("/api/ai/chat")
async def kchat_ai_chat(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return JSONResponse({
            "error": "KCHAT AI is not configured yet. Add OPENAI_API_KEY to the Render environment."
        }, status_code=503)

    try:
        data = await request.json()
        raw_messages = data.get("messages", [])
        if not isinstance(raw_messages, list) or not raw_messages:
            return JSONResponse({"error": "Send a message to KCHAT AI."}, status_code=400)

        safe_messages = []
        for entry in raw_messages[-24:]:
            if not isinstance(entry, dict):
                continue
            role = entry.get("role")
            content = entry.get("content")
            if role not in ("user", "assistant") or not isinstance(content, str):
                continue
            content = content.strip()
            if content:
                safe_messages.append({"role": role, "content": content[:6000]})

        if not safe_messages or safe_messages[-1]["role"] != "user":
            return JSONResponse({"error": "Your latest message is missing."}, status_code=400)

        # Route image requests on the server as well as in the browser.
        latest_text = safe_messages[-1]["content"].strip()
        image_prompt = latest_text
        refusal_pattern = re.search(r'(?is)(?:can.t|cannot).*?(?:image|picture|photo).*?(?:prompt|generator).*?[“"]([^”"]{20,1800})[”"]', latest_text)
        if refusal_pattern:
            image_prompt = refusal_pattern.group(1).strip()
        direct_image_request = re.search(r'(?is)\b(?:create|generate|draw|render|make|produce)\b.{0,140}\b(?:image|picture|photo|illustration|artwork|poster|logo|portrait)\b|\b(?:image|picture|photo|illustration|artwork|poster|logo|portrait)\b.{0,100}\b(?:create|generate|draw|render|make)\b', latest_text)
        if refusal_pattern or direct_image_request:
            if os.environ.get("CLOUDFLARE_ACCOUNT_ID") and os.environ.get("CLOUDFLARE_API_TOKEN"):
                generated_images = await cloudflare_generate_images(image_prompt, 1)
            elif api_key:
                image_client = AsyncOpenAI(api_key=api_key)
                image_result = await image_client.images.generate(
                    model=os.environ.get("OPENAI_IMAGE_MODEL", "gpt-image-2.5-flare"),
                    prompt=image_prompt[:2000],
                    n=1,
                    size="2048x1152",
                    quality="max",
                    output_format="png",
                    safety_identifier=hashlib.sha256(str(account["id"]).encode("utf-8")).hexdigest()
                )
                generated_images = ["data:image/png;base64," + item.b64_json for item in (image_result.data or []) if item.b64_json]
            else:
                return JSONResponse({"error": "Image generation is not configured. Add CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in Render."}, status_code=503)
            if not generated_images:
                return JSONResponse({"error": "KCHAT AI did not receive any generated images. Please try again."}, status_code=502)
            return {"success": True, "images": generated_images, "reply": "Here is your image."}

        client = AsyncOpenAI(api_key=api_key)
        response = await client.responses.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-6-luna"),
            instructions=(
                "You are KCHAT AI, a helpful conversational assistant inside the KCHAT app. "
                "Respond naturally and accurately like a capable ChatGPT assistant. "
                "Help with explanations, learning, writing, coding, planning and problem-solving. "
                "Use the conversation history to understand follow-up questions. "
                "Be clear, respectful and honest about uncertainty. Never claim to have performed "
                "actions outside the chat unless a connected tool actually did so."
            ),
            input=safe_messages,
            max_output_tokens=1400
        )
        answer = (response.output_text or "").strip()
        if not answer:
            return JSONResponse({"error": "KCHAT AI could not produce a reply. Please try again."}, status_code=502)
        return {"success": True, "reply": answer}

    except Exception as error:
        print("KCHAT AI request error:", repr(error))
        detail = str(error).strip()
        if "api_key" in detail.lower() or "authentication" in detail.lower() or "401" in detail:
            message = "OpenAI rejected the API key. Check OPENAI_API_KEY in Render."
        elif "quota" in detail.lower() or "billing" in detail.lower() or "429" in detail:
            message = "Your OpenAI API account has no available quota. Check API billing and usage limits."
        elif "model" in detail.lower() and ("not found" in detail.lower() or "access" in detail.lower()):
            message = "The selected OpenAI model is unavailable to this API project. Check OPENAI_MODEL access."
        else:
            message = "OpenAI connection error: " + (detail[:260] if detail else "Unknown error")
        return JSONResponse({"error": message}, status_code=502)



@app.post("/api/ai/image")
async def kchat_ai_image(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    cloudflare_ready = bool(
        os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        and os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    )
    if not api_key and not cloudflare_ready:
        return JSONResponse({"error": "Image generation is not configured. Add CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in Render."}, status_code=503)

    try:
        data = await request.json()
        prompt = str(data.get("prompt", "")).strip()
        if not prompt:
            return JSONResponse({"error": "Describe the picture you want KCHAT AI to create."}, status_code=400)
        if len(prompt) > 2000:
            return JSONResponse({"error": "Please keep the image description under 2,000 characters."}, status_code=400)

        count = max(1, min(4, int(data.get("count", 1))))
        if cloudflare_ready:
            images = await cloudflare_generate_images(prompt, count)
        else:
            client = AsyncOpenAI(api_key=api_key)
            size = str(data.get("size", "2048x1152"))
            if size not in ("2048x1152", "1152x2048", "2048x2048"):
                size = "2048x1152"
            result = await client.images.generate(
                model=os.environ.get("OPENAI_IMAGE_MODEL", "gpt-image-2.5-flare"),
                prompt=prompt,
                n=count,
                size=size,
                quality="max",
                output_format="png",
                safety_identifier=hashlib.sha256(str(account["id"]).encode("utf-8")).hexdigest()
            )
            images = ["data:image/png;base64," + item.b64_json for item in (result.data or []) if item.b64_json]
        if not images:
            return JSONResponse({"error": "KCHAT AI did not return an image. Please try again."}, status_code=502)
        return {"success": True, "images": images}

    except Exception as error:
        print("KCHAT AI image generation error:", repr(error))
        detail = str(error).strip()
        lower = detail.lower()
        if "api_key" in lower or "authentication" in lower or "401" in lower:
            message = "OpenAI rejected the API key. Check OPENAI_API_KEY in Render."
        elif "quota" in lower or "billing" in lower or "429" in lower:
            message = "Image generation has no available API quota. Check OpenAI API billing and usage limits."
        elif "verification" in lower or "organization" in lower:
            message = "Your OpenAI organization may need verification before image generation. Check the OpenAI developer dashboard."
        elif "model" in lower and ("not found" in lower or "access" in lower):
            message = "The image model is unavailable to this API project. Check OPENAI_IMAGE_MODEL access."
        else:
            message = "Image generation failed: " + (detail[:220] if detail else "Please try again.")
        return JSONResponse({"error": message}, status_code=502)


def _openai_video_request(path, api_key, method="GET", payload=None):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        "https://api.openai.com/v1" + path,
        data=body,
        method=method,
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read(), response.headers.get("Content-Type", "application/json")


@app.post("/api/ai/video")
async def kchat_ai_video_create(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return JSONResponse({"error": "Add OPENAI_API_KEY to the Render environment."}, status_code=503)
    try:
        data = await request.json()
        prompt = str(data.get("prompt", "")).strip()
        if not prompt:
            return JSONResponse({"error": "Describe the video you want KCHAT AI to create."}, status_code=400)
        if len(prompt) > 2000:
            return JSONResponse({"error": "Keep the video description under 2,000 characters."}, status_code=400)
        size = str(data.get("size", "1280x720"))
        if size not in ("1280x720", "720x1280"):
            size = "1280x720"
        payload = {
            "model": os.environ.get("OPENAI_VIDEO_MODEL", "sora-2"),
            "prompt": prompt,
            "size": size,
            "seconds": str(data.get("seconds", "8"))
        }
        raw, _ = await asyncio.to_thread(_openai_video_request, "/videos", api_key, "POST", payload)
        job = json.loads(raw.decode("utf-8"))
        return {"success": True, "id": job.get("id"), "status": job.get("status", "queued")}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        print("KCHAT AI video create error:", detail[:1000])
        return JSONResponse({"error": "OpenAI video generation failed: " + detail[:220]}, status_code=502)
    except Exception as error:
        print("KCHAT AI video create error:", repr(error))
        return JSONResponse({"error": "Video generation failed: " + str(error)[:220]}, status_code=502)


@app.get("/api/ai/video/{video_id}")
async def kchat_ai_video_status(video_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return JSONResponse({"error": "KCHAT AI is not configured."}, status_code=503)
    if not re.fullmatch(r"video_[A-Za-z0-9_-]+", video_id):
        return JSONResponse({"error": "Invalid video job."}, status_code=400)
    try:
        raw, _ = await asyncio.to_thread(_openai_video_request, "/videos/" + video_id, api_key)
        job = json.loads(raw.decode("utf-8"))
        return {"success": True, "status": job.get("status"), "error": job.get("error")}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        return JSONResponse({"error": "Could not check video status: " + detail[:180]}, status_code=502)
    except Exception as error:
        return JSONResponse({"error": "Could not check video status: " + str(error)[:180]}, status_code=502)


@app.get("/api/ai/video/{video_id}/content")
async def kchat_ai_video_content(video_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return JSONResponse({"error": "KCHAT AI is not configured."}, status_code=503)
    if not re.fullmatch(r"video_[A-Za-z0-9_-]+", video_id):
        return JSONResponse({"error": "Invalid video job."}, status_code=400)
    try:
        raw, content_type = await asyncio.to_thread(_openai_video_request, "/videos/" + video_id + "/content", api_key)
        return Response(content=raw, media_type="video/mp4", headers={"Content-Disposition": 'inline; filename="kchat-ai-video.mp4"'})
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        return JSONResponse({"error": "Video is not ready or could not be downloaded: " + detail[:180]}, status_code=502)
    except Exception as error:
        return JSONResponse({"error": "Could not load generated video: " + str(error)[:180]}, status_code=502)

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


@app.post("/api/contacts/match")
async def match_phone_contacts(request: Request):
    account = get_account_from_request(request)

    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        supplied = data.get("phone_numbers", [])

        if not isinstance(supplied, list) or len(supplied) > 500:
            return JSONResponse({
                "error": "Send a list of up to 500 phone numbers."
            }, status_code=400)

        keys = set()
        for value in supplied:
            key = phone_key(value)
            if not key:
                continue
            keys.add(key)
            # Match common Ugandan phonebook formats (07... and +2567...).
            if len(key) == 10 and key.startswith("0"):
                keys.add("256" + key[1:])
            elif len(key) == 12 and key.startswith("256"):
                keys.add("0" + key[3:])
        keys = sorted(keys)

        if not keys:
            return {"matches": []}

        placeholders = ", ".join(["%s"] * len(keys))
        with get_db() as conn:
            rows = conn.execute(f"""
                SELECT id, username, phone_number, phone_key, profile_picture, about
                FROM accounts
                WHERE phone_key IN ({placeholders})
                AND id != %s
                AND NOT EXISTS (
                    SELECT 1 FROM blocked_users
                    WHERE (owner_id = %s AND blocked_id = accounts.id)
                       OR (owner_id = accounts.id AND blocked_id = %s)
                )
                ORDER BY username
            """, (*keys, account["id"], account["id"], account["id"])).fetchall()

        return {
            "matches": [
                {
                    "username": row["username"],
                    "phone_number": row["phone_number"],
                    "phone_key": row["phone_key"],
                    "profile_picture": row["profile_picture"],
                    "about": row["about"]
                }
                for row in rows
            ]
        }

    except Exception as error:
        print("Phone contact matching error:", error)
        return JSONResponse({
            "error": "Could not match phone contacts."
        }, status_code=500)


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
            SELECT id, username, phone_number, profile_picture, about
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
        # Only return the registered phone number to the account owner.
        "phone_number": profile["phone_number"] if profile["id"] == account["id"] else None,
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
                "last_message": (
                    "📷 Photo"
                    if str(row["text"]).startswith("data:image/")
                    else row["text"]
                ),
                "last_message_id": row["id"],
                "last_message_time": (
                    row["created_at"].isoformat()
                    if row["created_at"] else None
                ),
                "last_message_sender": sender,
                "last_message_status": (
                    (
                        "sent"
                        if not get_privacy_settings(peer_profile["id"]).get("delivery_receipts", True)
                        else (
                            "delivered"
                            if row["status"] == "read"
                            and not get_privacy_settings(peer_profile["id"]).get("read_receipts", True)
                            else row["status"]
                        )
                    )
                    if sender.lower() == account["username"].lower() and peer_profile
                    else row["status"]
                ),
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

@app.get("/api/presence/{username}")
async def get_contact_presence(username: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    peer_name = username.strip()[:30]
    with get_db() as conn:
        peer = conn.execute("""
            SELECT id, username FROM accounts
            WHERE username_key = %s
        """, (peer_name.lower(),)).fetchone()

    if not peer:
        return JSONResponse({"error": "User not found."}, status_code=404)

    allowed = can_view_presence(peer["id"], account["id"])
    return {
        "success": True,
        "username": peer["username"],
        "online": bool(allowed and is_user_online(peer["username"]))
    }


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
            SELECT m.*,
                (m.edited_at IS NOT NULL) AS edited,
                EXISTS (
                    SELECT 1 FROM pinned_messages pm
                    WHERE pm.message_id = m.id AND pm.owner_id = %s
                ) AS pinned_by_me
            FROM messages m
            WHERE m.type = 'private'
            AND (
                (LOWER(m.username) = %s AND LOWER(m.recipient) = %s)
                OR
                (LOWER(m.username) = %s AND LOWER(m.recipient) = %s)
            )
            AND (m.expires_at IS NULL OR m.expires_at > NOW())
            AND NOT EXISTS (
                SELECT 1 FROM message_hidden mh
                WHERE mh.message_id = m.id AND mh.owner_id = %s
            )
            ORDER BY m.created_at ASC
        """, (
            account["id"],
            account["username"].lower(), peer["username"].lower(),
            peer["username"].lower(), account["username"].lower(),
            account["id"]
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



@app.post("/api/messages/{message_id}/hide")
async def hide_message_for_me(message_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    with get_db() as conn:
        message = conn.execute("""
            SELECT id, type, username, recipient
            FROM messages WHERE id = %s
        """, (message_id,)).fetchone()
        if not message or message["type"] != "private":
            return JSONResponse({"error": "Message not found."}, status_code=404)
        participant = account["username"].lower()
        if participant not in {
            (message["username"] or "").lower(),
            (message["recipient"] or "").lower()
        }:
            return JSONResponse({"error": "You cannot remove this message."}, status_code=403)
        conn.execute("""
            INSERT INTO message_hidden (owner_id, message_id)
            VALUES (%s, %s) ON CONFLICT DO NOTHING
        """, (account["id"], message_id))

    return {"success": True, "message": "Message deleted from your conversation."}


@app.post("/api/messages/{message_id}/pin")
async def pin_message_for_me(message_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        data = {}
    pinned = data.get("pinned", True)
    if not isinstance(pinned, bool):
        return JSONResponse({"error": "Pinned must be true or false."}, status_code=400)

    with get_db() as conn:
        message = conn.execute("""
            SELECT id, type, username, recipient
            FROM messages WHERE id = %s
        """, (message_id,)).fetchone()
        if not message or message["type"] != "private":
            return JSONResponse({"error": "Message not found."}, status_code=404)
        participant = account["username"].lower()
        if participant not in {
            (message["username"] or "").lower(),
            (message["recipient"] or "").lower()
        }:
            return JSONResponse({"error": "You cannot pin this message."}, status_code=403)

        if pinned:
            conn.execute("""
                INSERT INTO pinned_messages (owner_id, message_id)
                VALUES (%s, %s) ON CONFLICT (owner_id, message_id)
                DO UPDATE SET pinned_at = NOW()
            """, (account["id"], message_id))
        else:
            conn.execute("""
                DELETE FROM pinned_messages
                WHERE owner_id = %s AND message_id = %s
            """, (account["id"], message_id))

    return {"success": True, "pinned": pinned}


@app.put("/api/messages/{message_id}/edit")
async def edit_private_message(message_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        new_text = str(data.get("text", "")).strip()
        if not new_text:
            return JSONResponse({"error": "Message cannot be empty."}, status_code=400)
        if len(new_text) > 20000:
            return JSONResponse({"error": "Message is too long."}, status_code=400)

        with get_db() as conn:
            message = conn.execute("""
                SELECT id, type, username, recipient, revoked_at, text
                FROM messages WHERE id = %s
            """, (message_id,)).fetchone()
            if not message or message["type"] != "private":
                return JSONResponse({"error": "Message not found."}, status_code=404)
            if message["username"].lower() != account["username"].lower():
                return JSONResponse({"error": "You can only edit messages you sent."}, status_code=403)
            if message["revoked_at"]:
                return JSONResponse({"error": "A deleted message cannot be edited."}, status_code=409)
            if str(message["text"]).startswith("data:image/"):
                return JSONResponse({"error": "Photo messages cannot be edited."}, status_code=400)

            conn.execute("""
                UPDATE messages SET text = %s, edited_at = NOW()
                WHERE id = %s
            """, (new_text, message_id))

        event = {
            "type": "message_edited",
            "id": message_id,
            "text": new_text,
            "edited": True
        }
        for websocket in connected_sockets_for(message["recipient"]):
            try:
                await websocket.send_json(event)
            except Exception as error:
                print("Message edit notification error:", error)

        return {"success": True, "text": new_text, "edited": True}
    except Exception as error:
        print("Message edit error:", error)
        return JSONResponse({"error": "Could not edit this message."}, status_code=500)


@app.post("/api/messages")
async def send_private_message(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        recipient_name = str(data.get("recipient", data.get("to", ""))).strip()[:30]
        message_text = str(data.get("text", "")).strip()
        is_image = bool(re.fullmatch(
            r"data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}",
            message_text
        ))
        if not recipient_name or not message_text:
            return JSONResponse({"error": "Choose a recipient and enter a message."}, status_code=400)
        if is_image and len(message_text) > 3_400_000:
            return JSONResponse({
                "error": "That photo is too large after compression. Choose a smaller photo."
            }, status_code=413)
        if not is_image and len(message_text) > 10000:
            return JSONResponse({
                "error": "Messages cannot exceed 10,000 characters."
            }, status_code=413)
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
            "text": message_text if is_image else message_text[:10000],
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
        "edited": bool(row.get("edited_at")),
        "pinned_by_me": bool(row.get("pinned_by_me", False)),
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
        visible_online = bool(
            can_view_presence(row["id"], account["id"])
            and is_user_online(username)
        )
        try:
            await websocket.send_json({
                "type": "presence",
                "username": username,
                "online": visible_online
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

            if message_type == "typing":
                recipient = str(data.get("to", "")).strip()[:30]
                active = data.get("active") is True
                if not recipient or recipient.lower() == username.lower():
                    continue
                with get_db() as conn:
                    target = conn.execute("""
                        SELECT id, username FROM accounts
                        WHERE username_key = %s
                    """, (recipient.lower(),)).fetchone()
                if not target or users_blocked(account["id"], target["id"]):
                    continue
                event = {
                    "type": "typing",
                    "username": username,
                    "active": active
                }
                for target_socket in connected_sockets_for(target["username"]):
                    try:
                        await target_socket.send_json(event)
                    except Exception as error:
                        print("Typing notification error:", error)

            elif message_type == "chat":
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
# KCHAT STATUS UPDATES (24-HOUR STORIES)
# ============================================================

def ensure_status_table():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS status_updates (
                id TEXT PRIMARY KEY,
                owner_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                text TEXT NOT NULL DEFAULT '',
                media_data TEXT,
                media_type TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
            )
        """)
        conn.execute("""
            ALTER TABLE status_updates
            ADD COLUMN IF NOT EXISTS background TEXT NOT NULL DEFAULT '#546E7A'
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS status_updates_owner_expiry_idx
            ON status_updates(owner_id, expires_at DESC)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS status_views (
                status_id TEXT NOT NULL REFERENCES status_updates(id) ON DELETE CASCADE,
                viewer_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (status_id, viewer_id)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS status_views_status_idx
            ON status_views(status_id, viewed_at DESC)
        """)


def get_status_view_details(status_id):
    with get_db() as conn:
        viewers = conn.execute("""
            SELECT a.username, a.profile_picture, v.viewed_at
            FROM status_views v JOIN accounts a ON a.id = v.viewer_id
            WHERE v.status_id = %s ORDER BY v.viewed_at DESC
        """, (status_id,)).fetchall()
    return {
        "count": len(viewers),
        "viewers": [{"username": viewer["username"], "profile_picture": viewer["profile_picture"],
                     "viewed_at": viewer["viewed_at"].isoformat()} for viewer in viewers]
    }


@app.get("/api/statuses")
async def get_statuses(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        ensure_status_table()
        # Load the owner's statuses independently from contact statuses.
        # This guarantees that My status still loads even if the contacts
        # lookup encounters a problem.
        with get_db() as conn:
            own_rows = conn.execute("""
                SELECT s.id, s.owner_id, a.username, a.profile_picture, s.text,
                       s.media_data, s.media_type, s.background, s.created_at, s.expires_at
                FROM status_updates s
                JOIN accounts a ON a.id = s.owner_id
                WHERE s.owner_id = %s AND s.expires_at > NOW()
                ORDER BY s.created_at DESC
            """, (account["id"],)).fetchall()

        contact_rows = []
        try:
            with get_db() as conn:
                contact_rows = conn.execute("""
                    SELECT s.id, s.owner_id, a.username, a.profile_picture, s.text,
                           s.media_data, s.media_type, s.background, s.created_at, s.expires_at
                    FROM status_updates s
                    JOIN accounts a ON a.id = s.owner_id
                    JOIN contacts c ON c.contact_id = s.owner_id
                    WHERE c.owner_id = %s
                      AND s.owner_id <> %s
                      AND s.expires_at > NOW()
                    ORDER BY s.created_at DESC
                """, (account["id"], account["id"])).fetchall()
        except Exception as contact_error:
            print("Contact status lookup warning:", contact_error)

        rows = list(own_rows) + list(contact_rows)
        rows.sort(key=lambda row: row["created_at"], reverse=True)

        visible_rows = []
        for row in rows:
            # Use the immutable account ID to identify the viewer's own
            # statuses. Usernames can change in case or spelling.
            is_mine = str(row["owner_id"]) == str(account["id"])
            if not is_mine:
                owner_privacy = get_privacy_settings(row["owner_id"])
                audience = owner_privacy.get("status_audience", "all_contacts")
                excluded = {str(name).lower() for name in owner_privacy.get("status_excluded", [])}
                allowed = {str(name).lower() for name in owner_privacy.get("status_allowed", [])}
                viewer_name = account["username"].lower()
                if audience == "my_contacts_except" and viewer_name in excluded:
                    continue
                if audience == "only_share_with" and viewer_name not in allowed:
                    continue
            visible_rows.append(row)

        return {
            "success": True,
            "statuses": [{
                "id": row["id"],
                "username": row["username"],
                "profile_picture": row["profile_picture"],
                "text": row["text"],
                "media_data": row["media_data"],
                "media_type": row["media_type"],
                "background": row["background"] or "#546E7A",
                "created_at": row["created_at"].isoformat(),
                "expires_at": row["expires_at"].isoformat(),
                "is_mine": str(row["owner_id"]) == str(account["id"]),
                "view_count": (
                    get_status_view_details(row["id"])["count"]
                    if str(row["owner_id"]) == str(account["id"]) else None
                ),
                "viewers": (
                    get_status_view_details(row["id"])["viewers"]
                    if str(row["owner_id"]) == str(account["id"]) else []
                )
            } for row in visible_rows]
        }
    except Exception as error:
        print("Get statuses error:", error)
        return JSONResponse({"error": "Could not load status updates."}, status_code=500)


@app.post("/api/statuses/{status_id}/view")
async def record_status_view(status_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    try:
        ensure_status_table()
        with get_db() as conn:
            status = conn.execute("""
                SELECT id, owner_id FROM status_updates
                WHERE id = %s AND expires_at > NOW()
            """, (status_id,)).fetchone()
            if not status:
                return JSONResponse({"error": "Status not found or expired."}, status_code=404)
            if str(status["owner_id"]) != str(account["id"]):
                conn.execute("""
                    INSERT INTO status_views (status_id, viewer_id)
                    VALUES (%s, %s)
                    ON CONFLICT (status_id, viewer_id)
                    DO UPDATE SET viewed_at = NOW()
                """, (status_id, account["id"]))
        return {"success": True}
    except Exception as error:
        print("Record status view error:", error)
        return JSONResponse({"error": "Could not record status view."}, status_code=500)


@app.post("/api/statuses")
async def create_status(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)

    try:
        data = await request.json()
        text_value = str(data.get("text", "")).strip()[:700]
        media_data = data.get("media_data")
        media_type = data.get("media_type")
        background = str(data.get("background") or "#546E7A")
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", background):
            background = "#546E7A"

        if media_data is not None:
            if not isinstance(media_data, str) or len(media_data) > 7_000_000:
                return JSONResponse({"error": "Media is too large. Choose a smaller file."}, status_code=413)
            allowed_media = media_data.startswith("data:image/") or media_data.startswith("data:video/") or media_data.startswith("data:audio/")
            if not allowed_media:
                return JSONResponse({"error": "Choose an image, video, or audio recording."}, status_code=400)
            if media_type not in ("image", "video", "audio"):
                media_type = "audio" if media_data.startswith("data:audio/") else ("video" if media_data.startswith("data:video/") else "image")

        if not text_value and not media_data:
            return JSONResponse({"error": "Write something or choose a photo/video."}, status_code=400)

        ensure_status_table()
        status_id = uuid.uuid4().hex
        with get_db() as conn:
            row = conn.execute("""
                INSERT INTO status_updates
                    (id, owner_id, text, media_data, media_type, background)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING created_at, expires_at
            """, (status_id, account["id"], text_value, media_data, media_type, background)).fetchone()

        return {
            "success": True,
            "message": "Status shared.",
            "status": {
                "id": status_id,
                "username": account["username"],
                "text": text_value,
                "media_data": media_data,
                "media_type": media_type,
                "background": background,
                "created_at": row["created_at"].isoformat(),
                "expires_at": row["expires_at"].isoformat(),
                "is_mine": True
            }
        }
    except Exception as error:
        print("Create status error:", error)
        return JSONResponse({"error": "Could not share this status."}, status_code=500)




@app.put("/api/statuses/{status_id}")
async def update_status(status_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    try:
        data = await request.json()
        text_value = str(data.get("text", "")).strip()[:700]
        background = str(data.get("background") or "#546E7A")
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", background):
            background = "#546E7A"
        ensure_status_table()
        with get_db() as conn:
            row = conn.execute("""
                UPDATE status_updates SET text = %s, background = %s
                WHERE id = %s AND owner_id = %s AND expires_at > NOW()
                RETURNING id, text, created_at, expires_at, media_data, media_type, background
            """, (text_value, background, status_id, account["id"])).fetchone()
        if not row:
            return JSONResponse({"error": "Status not found or expired."}, status_code=404)
        return {"success": True, "status": {"id": row["id"], "username": account["username"], "text": row["text"], "media_data": row["media_data"], "media_type": row["media_type"], "background": row["background"] or "#546E7A", "created_at": row["created_at"].isoformat(), "expires_at": row["expires_at"].isoformat(), "is_mine": True}}
    except Exception as error:
        print("Update status error:", error)
        return JSONResponse({"error": "Could not update this status."}, status_code=500)

@app.delete("/api/statuses/{status_id}")
async def delete_status(status_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    try:
        ensure_status_table()
        with get_db() as conn:
            result = conn.execute("""
                DELETE FROM status_updates
                WHERE id = %s AND owner_id = %s
                RETURNING id
            """, (status_id, account["id"])).fetchone()
        if not result:
            return JSONResponse({"error": "Status not found."}, status_code=404)
        return {"success": True, "message": "Status deleted."}
    except Exception as error:
        print("Delete status error:", error)
        return JSONResponse({"error": "Could not delete this status."}, status_code=500)


# ============================================================
# KCHAT CHANNEL DIRECTORY
# ============================================================

def ensure_channels_tables():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                owner_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY(channel_id, account_id)
            )
        """)


@app.get("/api/channels")
async def list_channels(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    try:
        ensure_channels_tables()
        with get_db() as conn:
            rows = conn.execute("""
                SELECT c.id, c.name, c.description, c.created_at,
                       a.username AS owner,
                       EXISTS(
                           SELECT 1 FROM channel_members m
                           WHERE m.channel_id = c.id AND m.account_id = %s
                       ) AS following,
                       (SELECT COUNT(*) FROM channel_members m
                        WHERE m.channel_id = c.id) AS followers
                FROM channels c
                JOIN accounts a ON a.id = c.owner_id
                ORDER BY c.created_at DESC
            """, (account["id"],)).fetchall()
        return {"success": True, "channels": [{
            "id": row["id"], "name": row["name"],
            "description": row["description"], "owner": row["owner"],
            "following": row["following"], "followers": row["followers"],
            "created_at": row["created_at"].isoformat()
        } for row in rows]}
    except Exception as error:
        print("List channels error:", error)
        return JSONResponse({"error": "Could not load channels."}, status_code=500)


@app.post("/api/channels")
async def create_channel(request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    try:
        data = await request.json()
        name = str(data.get("name", "")).strip()[:60]
        description = str(data.get("description", "")).strip()[:300]
        if len(name) < 2:
            return JSONResponse({"error": "Channel name must contain at least 2 characters."}, status_code=400)
        ensure_channels_tables()
        channel_id = uuid.uuid4().hex
        with get_db() as conn:
            conn.execute("""
                INSERT INTO channels (id, owner_id, name, description)
                VALUES (%s, %s, %s, %s)
            """, (channel_id, account["id"], name, description))
            conn.execute("""
                INSERT INTO channel_members (channel_id, account_id)
                VALUES (%s, %s)
            """, (channel_id, account["id"]))
        return {"success": True, "channel": {
            "id": channel_id, "name": name, "description": description,
            "owner": account["username"], "following": True, "followers": 1
        }}
    except Exception as error:
        print("Create channel error:", error)
        return JSONResponse({"error": "Could not create this channel."}, status_code=500)


@app.post("/api/channels/{channel_id}/follow")
async def follow_channel(channel_id: str, request: Request):
    account = get_account_from_request(request)
    if not account:
        return JSONResponse({"error": "Please log in again."}, status_code=401)
    try:
        ensure_channels_tables()
        with get_db() as conn:
            exists = conn.execute(
                "SELECT id FROM channels WHERE id = %s", (channel_id,)
            ).fetchone()
            if not exists:
                return JSONResponse({"error": "Channel not found."}, status_code=404)
            conn.execute("""
                INSERT INTO channel_members (channel_id, account_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING
            """, (channel_id, account["id"]))
        return {"success": True, "message": "Channel followed."}
    except Exception as error:
        print("Follow channel error:", error)
        return JSONResponse({"error": "Could not follow this channel."}, status_code=500)


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
