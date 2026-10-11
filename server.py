"""P2PChat v1.1 standalone relay server (single file).

Dependencies: pip install fastapi uvicorn python-multipart cryptography
Run: python server.py ; default listener 127.0.0.1:8000
Configure an HTTPS reverse proxy for public deployment; data is stored by default in server_data/ beside this file.
Thread pool: P2PCHAT_THREAD_TOKENS (default 100, maximum 512).
SQLite synchronous mode: P2PCHAT_SQLITE_SYNCHRONOUS (default FULL; options NORMAL/EXTRA).

The server only stores and relays E2E ciphertext and never holds client keys. Acknowledgements do not delete records; the recipient explicitly
deletes them. It uses SQLite WAL and a configurable thread pool; a single process keeps the replay cache effective.
This file matches the protocol implementation in client.py; do not mix it with older project protocols.
"""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import base64
from collections import OrderedDict
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Iterator

import anyio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse

DATA_DIR = Path(
    os.environ.get("P2PCHAT_SERVER_DATA", Path(__file__).with_name("server_data"))
).resolve()
FILES_DIR = DATA_DIR / "files"
DATABASE_PATH = DATA_DIR / "relay.sqlite3"
DATA_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)
MAX_FILE_BYTES = 2 * 1024**3  # Maximum accepted encrypted upload size.
IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")  # Raw X25519 public key in Base64URL.
_replay_cache: OrderedDict[tuple[str, str], float] = OrderedDict()
_replay_lock = threading.Lock()
AUTH_WINDOW_SECONDS = 300
DEFAULT_THREAD_TOKENS = 100
MAX_THREAD_TOKENS = 512
SQLITE_SYNCHRONOUS = os.environ.get("P2PCHAT_SQLITE_SYNCHRONOUS", "FULL").upper()
SERVER_VERSION = "1.1"
if SQLITE_SYNCHRONOUS not in {"FULL", "NORMAL", "EXTRA"}:
    raise ValueError("P2PCHAT_SQLITE_SYNCHRONOUS must be FULL, NORMAL, or EXTRA")


def encode_base64url(data: bytes) -> str:
    """Encode bytes as URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_base64url(value: str) -> bytes:
    """Decode URL-safe Base64, restoring optional padding."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def raw_public_key(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def raw_private_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def public_identity(key) -> str:
    return encode_base64url(raw_public_key(key.public_key()))


def is_valid_identity(identity_id: str) -> bool:
    try:
        return (
            bool(IDENTITY_PATTERN.fullmatch(identity_id))
            and len(decode_base64url(identity_id)) == 32
        )
    except Exception:
        return False


SERVER_KEY_PATH = DATA_DIR / "server-key.json"
if SERVER_KEY_PATH.exists():
    SERVER_PRIVATE = X25519PrivateKey.from_private_bytes(
        decode_base64url(json.loads(SERVER_KEY_PATH.read_text("utf-8"))["private"])
    )
else:
    SERVER_PRIVATE = X25519PrivateKey.generate()
    SERVER_KEY_PATH.write_text(
        json.dumps(
            {
                "private": encode_base64url(raw_private_key(SERVER_PRIVATE)),
                "public": public_identity(SERVER_PRIVATE),
            }
        ),
        "utf-8",
    )
SERVER_ID = public_identity(SERVER_PRIVATE)


@contextmanager
def connect_database() -> Iterator[sqlite3.Connection]:
    """Yield a short-lived SQLite connection and always commit/close it."""
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute(f"PRAGMA synchronous={SQLITE_SYNCHRONOUS}")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    """Create the indexed relay schema and enable WAL for concurrent clients."""
    with connect_database() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(f"PRAGMA synchronous={SQLITE_SYNCHRONOUS}")
        connection.execute("PRAGMA wal_autocheckpoint=1000")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT NOT NULL UNIQUE,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                envelope TEXT NOT NULL,
                created REAL NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS messages_recipient_id
                ON messages(recipient, id);

            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                created REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS files_recipient ON files(recipient);
            """)


initialize_database()


def authenticate(identity_id: str, timestamp_text: str, nonce: str, proof: str) -> str:
    """Verify the identity's DH-HMAC proof and reject short-window replays."""
    if not is_valid_identity(identity_id):
        raise HTTPException(400, "invalid identity")
    try:
        timestamp = int(timestamp_text)
        shared = SERVER_PRIVATE.exchange(
            X25519PublicKey.from_public_bytes(decode_base64url(identity_id))
        )
        expected = hmac.new(
            shared, f"{identity_id}:{timestamp_text}:{nonce}".encode("ascii"), hashlib.sha256
        ).digest()
        if abs(time.time() - timestamp) > AUTH_WINDOW_SECONDS or not hmac.compare_digest(
            expected, decode_base64url(proof)
        ):
            raise ValueError
    except Exception:
        raise HTTPException(401, "authentication failed")
    with _replay_lock:
        now = time.monotonic()
        # Ordered insertion times allow expiry cleanup proportional to expired entries,
        # instead of scanning the full cache on every authenticated request.
        while _replay_cache:
            oldest_key, oldest_seen = next(iter(_replay_cache.items()))
            if now - oldest_seen <= AUTH_WINDOW_SECONDS:
                break
            _replay_cache.pop(oldest_key, None)
        cache_key = (identity_id, nonce)
        if cache_key in _replay_cache:
            raise HTTPException(409, "replayed request")
        _replay_cache[cache_key] = now
    return identity_id


@asynccontextmanager
async def lifespan(_app):
    initialize_database()
    configured_tokens = int(os.environ.get("P2PCHAT_THREAD_TOKENS", DEFAULT_THREAD_TOKENS))
    thread_limiter = anyio.to_thread.current_default_thread_limiter()
    thread_limiter.total_tokens = max(10, min(configured_tokens, MAX_THREAD_TOKENS))
    yield


app = FastAPI(title="P2PChat Standalone Relay", version=SERVER_VERSION, lifespan=lifespan)


@app.get("/")
def info():
    return {"name": "p2pchat-standalone", "version": SERVER_VERSION, "server_key": SERVER_ID}


@app.get("/api/server-key")
def server_key():
    return {"public_key": SERVER_ID}


@app.post("/api/send")
def send(
    identity: str = Form(...),
    ts: str = Form(...),
    nonce: str = Form(...),
    proof: str = Form(...),
    envelope: str = Form(...),
):
    authenticated_identity = authenticate(identity, ts, nonce, proof)
    if len(envelope.encode()) > 1_048_576:
        raise HTTPException(413, "envelope too large")
    try:
        envelope_data = json.loads(envelope)
    except Exception:
        raise HTTPException(400, "invalid envelope")
    if (
        not isinstance(envelope_data, dict)
        or envelope_data.get("v") != 1
        or envelope_data.get("from") != authenticated_identity
        or not is_valid_identity(envelope_data.get("to", ""))
        or not envelope_data.get("msg_id")
    ):
        raise HTTPException(400, "invalid envelope fields")
    if any(
        not isinstance(envelope_data.get(field), str) or not envelope_data[field]
        for field in ("salt", "nonce", "ct")
    ):
        raise HTTPException(400, "invalid ciphertext")
    with connect_database() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO messages(msg_id,sender,recipient,envelope,created) VALUES(?,?,?,?,?)",
            (
                envelope_data["msg_id"],
                authenticated_identity,
                envelope_data["to"],
                envelope,
                time.time(),
            ),
        )
    return {"ok": True, "msg_id": envelope_data["msg_id"]}


@app.post("/api/fetch")
def fetch(
    identity: str = Form(...),
    ts: str = Form(...),
    nonce: str = Form(...),
    proof: str = Form(...),
    after_id: int = Form(0),
    limit: int = Form(100),
):
    authenticated_identity = authenticate(identity, ts, nonce, proof)
    limit = max(1, min(int(limit), 300))
    with connect_database() as connection:
        message_rows = connection.execute(
            "SELECT id,envelope,created FROM messages WHERE recipient=? AND id>? ORDER BY id LIMIT ?",
            (authenticated_identity, max(0, after_id), limit),
        ).fetchall()
    return {
        "messages": [
            {
                "id": message_row["id"],
                "created": message_row["created"],
                "envelope": json.loads(message_row["envelope"]),
            }
            for message_row in message_rows
        ]
    }


@app.post("/api/ack")
def ack(
    identity: str = Form(...),
    ts: str = Form(...),
    nonce: str = Form(...),
    proof: str = Form(...),
    msg_ids: str = Form("[]"),
):
    authenticated_identity = authenticate(identity, ts, nonce, proof)
    try:
        message_ids = json.loads(msg_ids)
    except Exception:
        raise HTTPException(400, "invalid msg_ids")
    if not isinstance(message_ids, list):
        raise HTTPException(400, "invalid msg_ids")
    with connect_database() as connection:
        connection.executemany(
            "UPDATE messages SET acked=1 WHERE recipient=? AND msg_id=?",
            [(authenticated_identity, str(message_id)) for message_id in message_ids],
        )
    return {"ok": True}


@app.post("/api/delete")
def delete(
    identity: str = Form(...),
    ts: str = Form(...),
    nonce: str = Form(...),
    proof: str = Form(...),
    msg_ids: str = Form("[]"),
    file_ids: str = Form("[]"),
):
    authenticated_identity = authenticate(identity, ts, nonce, proof)
    try:
        message_ids = json.loads(msg_ids)
        file_identifiers = json.loads(file_ids)
    except Exception:
        raise HTTPException(400, "invalid ids")
    if not isinstance(message_ids, list) or not isinstance(file_identifiers, list):
        raise HTTPException(400, "invalid ids")
    removed_paths = []
    with connect_database() as connection:
        connection.executemany(
            "DELETE FROM messages WHERE recipient=? AND msg_id=?",
            [(authenticated_identity, str(message_id)) for message_id in message_ids],
        )
        for file_id in file_identifiers:
            row = connection.execute(
                "SELECT path FROM files WHERE recipient=? AND file_id=?",
                (authenticated_identity, str(file_id)),
            ).fetchone()
            if row:
                removed_paths.append(row["path"])
                connection.execute("DELETE FROM files WHERE file_id=?", (str(file_id),))
    for file_path in removed_paths:
        try:
            Path(file_path).unlink(missing_ok=True)
        except OSError:
            pass
    return {"ok": True}


@app.put("/api/upload/{to}/{file_id}")
async def upload_file_stream(
    to: str, file_id: str, request: Request, identity: str, ts: str, nonce: str, proof: str
):
    """Raw octet-stream streaming upload: bounded memory use for multi-GB files."""
    authenticated_identity = authenticate(identity, ts, nonce, proof)
    if not is_valid_identity(to) or not re.fullmatch(r"[a-f0-9]{32}", file_id):
        raise HTTPException(400, "invalid file metadata")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_FILE_BYTES:
                raise HTTPException(413, "file too large")
        except ValueError as error:
            raise HTTPException(400, "invalid content length") from error

    # Each concurrent upload gets its own staging path; file IDs cannot collide mid-upload.
    temporary_path = FILES_DIR / f"{file_id}.{secrets.token_hex(8)}.part"
    destination_path = FILES_DIR / (file_id + ".enc")
    size = 0
    destination_published = False
    try:
        async with await anyio.open_file(temporary_path, "wb") as output_file:
            async for chunk in request.stream():
                if not chunk:
                    continue
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise HTTPException(413, "file too large")
                await output_file.write(chunk)

        # Reserve the ID transactionally before publishing the final path.
        with connect_database() as connection:
            try:
                connection.execute(
                    "INSERT INTO files(file_id,sender,recipient,path,size,created) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        file_id,
                        authenticated_identity,
                        to,
                        str(destination_path),
                        size,
                        time.time(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise HTTPException(409, "file ID already exists") from error
            os.replace(temporary_path, destination_path)
            destination_published = True
    except Exception:
        temporary_path.unlink(missing_ok=True)
        if destination_published:
            destination_path.unlink(missing_ok=True)
        raise
    return {"ok": True, "size": size}


@app.get("/api/file/{file_id}")
def download(file_id: str, identity: str, ts: str, nonce: str, proof: str):
    authenticated_identity = authenticate(identity, ts, nonce, proof)
    with connect_database() as connection:
        row = connection.execute(
            "SELECT path FROM files WHERE file_id=? AND recipient=?",
            (file_id, authenticated_identity),
        ).fetchone()
    if not row:
        raise HTTPException(404, "file not found")
    file_path = Path(row["path"])
    if not file_path.is_file():
        raise HTTPException(410, "file content missing")
    return FileResponse(file_path, media_type="application/octet-stream", filename=file_id + ".enc")


if __name__ == "__main__":
    import uvicorn

    # Keep one process: the anti-replay nonce cache is process-local. Increase
    # P2PCHAT_THREAD_TOKENS for concurrent sync routes; multi-process scaling
    # requires a shared replay store (e.g. Redis) and is intentionally not enabled.
    uvicorn.run(
        app,
        host=os.environ.get("P2PCHAT_HOST", "127.0.0.1"),
        port=int(os.environ.get("P2PCHAT_PORT", "8000")),
    )
