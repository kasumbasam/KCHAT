
import json
import os
import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

app = FastAPI()

connected_users = {}
history = {}

HISTORY_FILE = "chat_history.json"


def load_history():
    global history

    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                history = json.load(file)
        except (json.JSONDecodeError, OSError):
            history = {}


def save_history():
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=4)
    except OSError:
        pass


load_history()


async def broadcast(room, message):
    for user in list(connected_users.get(room, [])):
        try:
            await user["websocket"].send_json(message)
        except Exception:
            pass


def find_users(room, username):
    return [
        user for user in connected_users.get(room, [])
        if user["username"].lower() == username.lower()
    ]


def private_key(room, user1, user2):
    names = sorted([user1.lower(), user2.lower()])
    return f"{room}:private:{names[0]}:{names[1]}"


async def send_online_users(room):
    users = list(dict.fromkeys(
        user["username"]
        for user in connected_users.get(room, [])
    ))

    await broadcast(room, {
        "type": "users",
        "users": users
    })


@app.get("/")
async def home():
    return FileResponse("index.html")


@app.websocket("/ws/{room}")
async def chat(websocket: WebSocket, room: str):
    await websocket.accept()

    username = websocket.query_params.get("username", "Guest")
    username = username.strip()[:30] or "Guest"
    room = room.strip()[:40] or "general"

    connected_users.setdefault(room, [])
    history.setdefault(room, [])

    connected_users[room].append({
        "username": username,
        "websocket": websocket
    })

    await websocket.send_json({
        "type": "welcome",
        "history": history[room],
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
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")

            if message_type == "chat":
                message = str(data.get("text", "")).strip()

                if not message:
                    continue

                item = {
                    "type": "chat",
                    "username": username,
                    "text": message
                }

                history[room].append(item)
                history[room] = history[room][-200:]

                save_history()
                await broadcast(room, item)

            elif message_type == "open_private":
                recipient = str(data.get("to", "")).strip()[:30]

                if not recipient or recipient.lower() == username.lower():
                    continue

                key = private_key(room, username, recipient)
                conversation = history.get(key, [])

                await websocket.send_json({
                    "type": "private_history",
                    "with": recipient,
                    "history": conversation
                })

                changed = False

                for item in conversation:
                    if (
                        item.get("to", "").lower() == username.lower()
                        and item.get("status") != "read"
                    ):
                        item["status"] = "read"
                        changed = True

                        for sender in find_users(room, item["username"]):
                            try:
                                await sender["websocket"].send_json({
                                    "type": "private_status",
                                    "id": item["id"],
                                    "status": "read"
                                })
                            except Exception:
                                pass

                if changed:
                    save_history()

            elif message_type == "private":
                recipient = str(data.get("to", "")).strip()[:30]
                message = str(data.get("text", "")).strip()

                if not recipient or not message:
                    continue

                if recipient.lower() == username.lower():
                    continue

                key = private_key(room, username, recipient)

                item = {
                    "id": uuid.uuid4().hex,
                    "type": "private",
                    "username": username,
                    "to": recipient,
                    "text": message,
                    "status": "sent"
                }

                history.setdefault(key, [])
                history[key].append(item)
                history[key] = history[key][-200:]

                save_history()

                await websocket.send_json(item)

                targets = find_users(room, recipient)
                delivered = False

                for target in targets:
                    try:
                        await target["websocket"].send_json(item)
                        delivered = True
                    except Exception:
                        pass

                if delivered:
                    item["status"] = "delivered"
                    save_history()

                    await websocket.send_json({
                        "type": "private_status",
                        "id": item["id"],
                        "status": "delivered"
                    })
                else:
                    await websocket.send_json({
                        "type": "system",
                        "text": recipient + " is offline. Message saved."
                    })

    except WebSocketDisconnect:
        pass

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
