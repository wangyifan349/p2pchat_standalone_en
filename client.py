"""P2PChat v1.1 standalone desktop client (single file; pairs with server.py in the same directory).

Dependencies: pip install PyQt6 cryptography requests
Run: python client.py
Data is stored by default in client_data/ beside this file; private keys stay on this machine only. This directory only needs this file and server.py.

Protocol: X25519 + HKDF-SHA256 + AES-256-GCM; files use an independent random key with 1 MiB chunked encryption;
message AAD binds sender/recipient/message ID. The server never decrypts. Warm orange theme with the blue channel fixed at 0.
"""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import base64, hashlib, hmac, json, os, secrets, shutil, sqlite3, sys, tempfile, time, uuid
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PyQt6.QtCore import QEvent, Qt, QObject, QRunnable, QThread, QThreadPool, pyqtSignal
from PyQt6.QtGui import QAction, QGuiApplication, QKeyEvent
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QMenu,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QFrame,
    QToolButton,
)

# ------------------------------- Crypto protocol ---------------------------------
CHUNK = 1024 * 1024
MSG_INFO = b"p2pchat/msg/v1"
FILE_INFO = b"p2pchat/file-chunk/v1"
AUTH_INFO = b"p2pchat/auth/v1"
AAD = b"p2pchat|msg|v1"
CHUNK_AAD = b"p2pchat|file-chunk|v1"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pubraw(k):
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def privraw(k):
    return k.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def ident(k):
    return b64e(pubraw(k.public_key()))


def hkdf(ikm, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def aad_msg(to, mid, fr):
    return b"|".join((AAD, to.encode(), mid.encode(), fr.encode()))


def seal(priv, to, payload, msg_id=None):
    fr = ident(priv)
    mid = msg_id or uuid.uuid4().hex
    salt = os.urandom(16)
    nonce = os.urandom(12)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(b64d(to)))
    key = hkdf(shared, salt, MSG_INFO)
    body = {
        **payload,
        "v": 1,
        "msg_id": mid,
        "from": fr,
        "to": to,
        "ts": time.time(),
    }
    ct = AESGCM(key).encrypt(
        nonce,
        json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode(),
        aad_msg(to, mid, fr),
    )
    return {
        "v": 1,
        "msg_id": mid,
        "from": fr,
        "to": to,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ct": b64e(ct),
    }


def open_envelope(priv, e):
    fr, to, mid = e["from"], e["to"], e["msg_id"]
    if e.get("v") != 1:
        raise ValueError("Unsupported message protocol version")
    if to != ident(priv):
        raise ValueError("Message recipient is not this identity")
    key = hkdf(
        priv.exchange(X25519PublicKey.from_public_bytes(b64d(fr))), b64d(e["salt"]), MSG_INFO
    )
    body = json.loads(AESGCM(key).decrypt(b64d(e["nonce"]), b64d(e["ct"]), aad_msg(to, mid, fr)))
    if body.get("v") != 1:
        raise ValueError("Unsupported message protocol version")
    if (body.get("from"), body.get("to"), body.get("msg_id")) != (fr, to, mid):
        raise ValueError("Envelope field validation failed")
    return body


def chunk_key(key, i):
    return hkdf(key, b"", FILE_INFO + i.to_bytes(8, "big"))


def encrypt_file(src, dst, key, progress):
    digest = hashlib.sha256()
    size = Path(src).stat().st_size
    done = i = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            block = fi.read(CHUNK)
            digest.update(block)
            done += len(block)
            ct = AESGCM(chunk_key(key, i)).encrypt(i.to_bytes(12, "big"), block, CHUNK_AAD)
            fo.write(len(ct).to_bytes(4, "big"))
            fo.write(ct)
            i += 1
            progress.emit(min(25, int(done / max(size, 1) * 25)))
            if len(block) < CHUNK:
                break
    return digest.hexdigest()


def decrypt_file(src, dst, key, expected, progress):
    digest = hashlib.sha256()
    i = done = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while h := fi.read(4):
            if len(h) != 4:
                raise ValueError("Corrupted file chunk header")
            n = int.from_bytes(h, "big")
            if n < 16 or n > CHUNK + 16:
                raise ValueError("Invalid file chunk length")
            ct = fi.read(n)
            if len(ct) != n:
                raise ValueError("Incomplete file chunk")
            block = AESGCM(chunk_key(key, i)).decrypt(i.to_bytes(12, "big"), ct, CHUNK_AAD)
            fo.write(block)
            digest.update(block)
            done += len(block)
            i += 1
            progress.emit(min(99, 25 + int(done / max(expected["size"], 1) * 74)))
    if digest.hexdigest() != expected["sha256"]:
        raise ValueError("File SHA-256 verification failed")


# -------------------------------- Local data ----------------------------------
ROOT = Path(__file__).resolve().parent / "client_data"
IDDIR = ROOT / "identities"
DL = ROOT / "downloads"
CFG = ROOT / "config.json"
DB = ROOT / "history.sqlite3"
for _p in (ROOT, IDDIR, DL):
    _p.mkdir(parents=True, exist_ok=True)


def read_config():
    try:
        return json.loads(CFG.read_text("utf-8"))
    except Exception:
        return {"server": "http://127.0.0.1:8000", "contacts": {}}


def write_config(c):
    tmp = CFG.with_suffix(".tmp")
    tmp.write_text(json.dumps(c, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, CFG)


def identities():
    out = []
    for p in sorted(IDDIR.glob("*.json")):
        try:
            out.append(json.loads(p.read_text("utf-8")))
        except Exception:
            continue
    return out


def make_identity(name):
    if not name or any(x in name for x in '\\/:*?"<>|'):
        raise ValueError("Invalid identity name")
    p = IDDIR / (name + ".json")
    if p.exists():
        raise ValueError("Identity name already exists")
    k = X25519PrivateKey.generate()
    d = {"name": name, "private": b64e(privraw(k)), "public": ident(k)}
    p.write_text(json.dumps(d, indent=2), "utf-8")
    return d


def dbconn():
    connection = sqlite3.connect(DB, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    _initialize_history_schema(connection)
    return connection


def _create_messages_table(connection: sqlite3.Connection) -> None:
    """Create the history table with per-identity message-ID uniqueness."""
    connection.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            identity TEXT NOT NULL,
            peer TEXT NOT NULL,
            msg_id TEXT NOT NULL,
            direction TEXT NOT NULL,
            kind TEXT NOT NULL,
            body TEXT NOT NULL,
            ts REAL NOT NULL,
            file_id TEXT,
            file_meta TEXT,
            local_path TEXT,
            status TEXT DEFAULT 'ok'
        )""")


def _initialize_history_schema(connection: sqlite3.Connection) -> None:
    """Migrate legacy global msg_id uniqueness without dropping local history."""
    _create_messages_table(connection)

    # Older builds used UNIQUE(msg_id), which blocks two local identities from
    # storing their respective sent/received copies of the same envelope.
    has_global_message_id_constraint = False
    for index in connection.execute("PRAGMA index_list(messages)").fetchall():
        if not index["unique"]:
            continue
        indexed_columns = [
            column["name"]
            for column in connection.execute(f"PRAGMA index_info('{index['name']}')").fetchall()
        ]
        if indexed_columns == ["msg_id"]:
            has_global_message_id_constraint = True
            break

    if has_global_message_id_constraint:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("ALTER TABLE messages RENAME TO messages_legacy")
            _create_messages_table(connection)
            connection.execute("""INSERT INTO messages (
                    id, identity, peer, msg_id, direction, kind, body, ts,
                    file_id, file_meta, local_path, status
                ) SELECT
                    id, identity, peer, msg_id, direction, kind, body, ts,
                    file_id, file_meta, local_path, status
                FROM messages_legacy""")
            connection.execute("DROP TABLE messages_legacy")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    # The same server message appears once in each identity's local history.
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS messages_identity_msg_id "
        "ON messages(identity, msg_id)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS msg_peer ON messages(identity, peer, ts, id)")
    connection.execute("""CREATE TABLE IF NOT EXISTS friend_requests (
            identity TEXT NOT NULL,
            peer TEXT NOT NULL,
            alias TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            updated REAL,
            PRIMARY KEY(identity, peer)
        )""")


def unique_download_path(directory: Path, filename: str) -> Path:
    """Choose a non-overwriting destination name for a newly received file."""
    safe_name = Path(filename).name or "received-file"
    candidate = directory / safe_name
    counter = 1
    while candidate.exists():
        candidate = directory / f"{Path(safe_name).stem} ({counter}){Path(safe_name).suffix}"
        counter += 1
    return candidate


def copy_file_with_progress(source: Path, destination: Path, progress) -> str:
    """Copy a potentially large file without blocking the GUI thread."""
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        progress.emit(100)
        return str(destination)

    temporary_path = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.part"
    )
    size = source.stat().st_size
    copied = 0
    try:
        with source.open("rb") as input_file, temporary_path.open("wb") as output_file:
            while block := input_file.read(CHUNK):
                output_file.write(block)
                copied += len(block)
                progress.emit(min(99, int(copied / max(size, 1) * 100)))
        shutil.copystat(source, temporary_path)
        os.replace(temporary_path, destination)
        progress.emit(100)
        return str(destination)
    finally:
        temporary_path.unlink(missing_ok=True)


class Api:
    def __init__(self, server, private):
        self.server = server.rstrip("/")
        self.private = private
        self.identity = ident(private)
        self._server_pub = None

    def auth(self):
        if self._server_pub is None:
            r = requests.get(self.server + "/api/server-key", timeout=10)
            r.raise_for_status()
            self._server_pub = b64d(r.json()["public_key"])
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        shared = self.private.exchange(X25519PublicKey.from_public_bytes(self._server_pub))
        proof = b64e(
            hmac.new(shared, f"{self.identity}:{ts}:{nonce}".encode(), hashlib.sha256).digest()
        )
        return {"identity": self.identity, "ts": ts, "nonce": nonce, "proof": proof}

    def post(self, path, data=None, timeout=60, files=None):
        form = self.auth()
        form.update(data or {})
        r = requests.post(self.server + path, data=form, files=files, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def fetch(self, after):
        return self.post("/api/fetch", {"after_id": after, "limit": 100})

    def send(self, e):
        return self.post("/api/send", {"envelope": json.dumps(e)})

    def ack(self, ids):
        return self.post("/api/ack", {"msg_ids": json.dumps(ids)})

    def upload(self, to, fid, path, progress):
        # Passing a real file stream lets requests use a known Content-Length without buffering
        # the encrypted payload in RAM. The worker thread keeps slow disks/network off the GUI.
        auth = self.auth()
        with open(path, "rb") as encrypted_file:
            r = requests.put(
                self.server + f"/api/upload/{to}/{fid}",
                params=auth,
                data=encrypted_file,
                timeout=900,
            )
        r.raise_for_status()
        progress.emit(89)
        return r.json()

    def download(self, fid, path):
        r = requests.get(
            self.server + "/api/file/" + fid, params=self.auth(), stream=True, timeout=900
        )
        r.raise_for_status()
        with open(path, "wb") as f:
            for block in r.iter_content(1024 * 1024):
                if block:
                    f.write(block)

    def delete(self, mids, fids):
        return self.post("/api/delete", {"msg_ids": json.dumps(mids), "file_ids": json.dumps(fids)})


# ------------------------- Background jobs; never block the GUI ----------------------------
class Signals(QObject):
    message = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str, int)
    done = pyqtSignal(str, object)
    failed = pyqtSignal(str, str)


class Poller(QThread):
    def __init__(self, api, priv, cursor):
        super().__init__()
        self.api = api
        self.priv = priv
        self.cursor = cursor
        self.sig = Signals()
        self.running = True

    def run(self):
        while self.running:
            try:
                items = self.api.fetch(self.cursor)["messages"]
                for item in items:
                    sid = int(item["id"])
                    e = item["envelope"]
                    try:
                        b = open_envelope(self.priv, e)
                    except Exception as ex:
                        self.sig.error.emit(f"Unable to decrypt message: {ex}")
                        self.cursor = max(self.cursor, sid)
                        continue
                    b["_server_id"] = sid
                    self.sig.message.emit(b)
                    try:
                        self.api.ack([e["msg_id"]])
                    except Exception as ex:
                        # ack is non-destructive; keep receiving despite a transient ack failure.
                        self.sig.error.emit(f"Message received, but server acknowledgement failed: {ex}")
                    self.cursor = max(self.cursor, sid)
            except Exception as ex:
                self.sig.error.emit(f"Server connection failed: {ex}")
            self.msleep(1200)

    def stop(self):
        self.running = False
        self.requestInterruption()


class Job(QRunnable):
    def __init__(self, key, fn):
        super().__init__()
        self.key = key
        self.fn = fn
        self.sig = Signals()

    def run(self):
        try:
            progress_reporter = _JobProgressReporter(self.key, self.sig.progress)
            self.sig.done.emit(self.key, self.fn(progress_reporter))
        except Exception as e:
            self.sig.failed.emit(self.key, str(e))


class _JobProgressReporter:
    """Adapt file helpers' one-value progress API to the GUI's keyed signal."""

    def __init__(self, task_key: str, progress_signal):
        self.task_key = task_key
        self.progress_signal = progress_signal

    def emit(self, percentage: int) -> None:
        self.progress_signal.emit(self.task_key, max(0, min(100, int(percentage))))


# ---------------------------------- GUI --------------------------------------
APP_VERSION = "1.1"
ORANGE = "#C85422"
BG = "#F4F2EF"
CARD = "#FFFFFF"
TEXT = "#29241F"
MUTED = "#7B7169"
STYLE = f"""
* {{ color:{TEXT}; font-family:'Microsoft YaHei UI','Segoe UI',sans-serif; font-size:14px; }}
QMainWindow,QDialog {{ background:{BG}; }}
QWidget#left {{ background:{CARD}; border-right:1px solid #E8E2DC; }}
QLineEdit,QTextEdit,QListWidget {{ background:{CARD}; border:1px solid #E4DDD6; border-radius:10px; padding:9px; selection-background-color:{ORANGE}; selection-color:white; }}
QLineEdit:focus,QTextEdit:focus {{ border:1px solid {ORANGE}; }}
QListWidget {{ outline:0; }}
QListWidget::item {{ padding:5px; border-radius:7px; }}
QListWidget::item:selected {{ background:#F8E9DF; color:{TEXT}; }}
QListWidget#chatMessages {{ background:transparent; border:0; padding:0; margin:0; }}
QListWidget#chatMessages::item {{ padding:0; border:0; }}
QListWidget#chatMessages::item:selected {{ background:transparent; }}
QPushButton {{ background:#EEE9E3; border:1px solid #E5DED7; border-radius:9px; padding:6px 12px; min-height:30px; }}
QPushButton:hover {{ background:#E8DED4; border-color:#D9CABC; }}
QPushButton:pressed {{ background:#DED1C5; }}
QPushButton#primary {{ background:{ORANGE}; border:1px solid {ORANGE}; color:white; font-weight:600; }}
QPushButton#primary:hover {{ background:#B5481C; border-color:#B5481C; }}
QToolButton {{ background:#F0ECE7; border:1px solid #E5DED7; border-radius:8px; }}
QToolButton:hover {{ background:#E8DED4; }}
QLabel#muted {{ color:{MUTED}; }}
QLabel#chatTitle {{ font-size:17px; font-weight:600; }}
QProgressBar {{ border:0; background:#E9E4DE; height:7px; border-radius:3px; }}
QProgressBar::chunk {{ background:{ORANGE}; border-radius:3px; }}
QMenu {{ background:{CARD}; border:1px solid #E4DDD6; padding:5px; }}
QMenu::item {{ padding:7px 24px 7px 12px; border-radius:5px; }}
QMenu::item:selected {{ background:#F8E9DF; color:{TEXT}; }}
QStatusBar {{ background:{CARD}; border-top:1px solid #E8E2DC; color:{MUTED}; }}
QSplitter::handle {{ background:transparent; width:1px; }}
"""


class Login(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"P2PChat v{APP_VERSION} · Login")
        self.resize(760, 680)
        self.setMinimumSize(620, 600)
        self.cfg = read_config()
        v = QVBoxLayout(self)
        v.setContentsMargins(38, 30, 38, 30)
        v.setSpacing(14)
        brand = QHBoxLayout()
        title = QLabel("P2PChat")
        title.setStyleSheet(f"font-size:32px;font-weight:700;color:{ORANGE}")
        brand.addWidget(title)
        version = QLabel(f"v{APP_VERSION}")
        version.setStyleSheet(
            f"color:{ORANGE};background:#F8E9DF;border-radius:9px;padding:4px 9px;font-size:12px;font-weight:600"
        )
        brand.addWidget(version, 0, Qt.AlignmentFlag.AlignBottom)
        brand.addStretch(1)
        v.addLayout(brand)
        subtitle = QLabel("Private chat, only for you and your contacts\nX25519 / AES-256-GCM end-to-end encryption · private key kept on this machine only")
        subtitle.setStyleSheet(f"font-size:15px;color:{MUTED}")
        v.addWidget(subtitle)
        f = QFormLayout()
        f.setSpacing(10)
        self.server = QLineEdit(self.cfg.get("server", "http://127.0.0.1:8000"))
        self.server.setMinimumHeight(40)
        f.addRow("Server", self.server)
        v.addLayout(f)
        self.list = QListWidget()
        self.list.setMinimumHeight(190)
        v.addWidget(self.list)
        for x in identities():
            item = QListWidgetItem(f"{x['name']}   ·   {x['public'][:12]}…{x['public'][-6:]}")
            item.setData(Qt.ItemDataRole.UserRole, x)
            self.list.addItem(item)
        row = QHBoxLayout()
        new = QPushButton("Create identity")
        new.clicked.connect(self.new_id)
        row.addWidget(new)
        row.addStretch(1)
        v.addLayout(row)
        self.pk = QLineEdit()
        self.pk.setReadOnly(True)
        self.pk.setMinimumHeight(46)
        self.pk.setPlaceholderText("After selecting an identity, your public key appears here")
        v.addWidget(self.pk)
        self.list.currentItemChanged.connect(self.update_pk)
        if self.list.count():
            self.list.setCurrentRow(0)
        enter = QPushButton("Enter chat")
        enter.setObjectName("primary")
        enter.setMinimumHeight(52)
        enter.setStyleSheet("font-size:18px;font-weight:bold")
        enter.clicked.connect(self.accept)
        v.addWidget(enter)

    def update_pk(self, *_):
        self.pk.setText(
            self.list.currentItem().data(Qt.ItemDataRole.UserRole)["public"]
            if self.list.currentItem()
            else ""
        )

    def new_id(self, _checked=False):
        n, ok = QInputDialog.getText(self, "Create identity", "Identity name")
        if ok:
            try:
                x = make_identity(n.strip())
                it = QListWidgetItem(f"{n}   ·   {x['public'][:12]}…{x['public'][-6:]}")
                it.setData(Qt.ItemDataRole.UserRole, x)
                self.list.addItem(it)
                self.list.setCurrentItem(it)
            except Exception as e:
                QMessageBox.warning(self, "Creation failed", str(e))

    def accept(self, _checked=False):
        if not self.list.currentItem():
            QMessageBox.warning(self, "Notice", "Create or select an identity first")
            return
        if not self.server.text().strip():
            QMessageBox.warning(self, "Notice", "Server address cannot be empty")
            return
        self.cfg["server"] = self.server.text().strip().rstrip("/")
        write_config(self.cfg)
        super().accept()

    def record(self):
        return self.list.currentItem().data(Qt.ItemDataRole.UserRole)


class ChatInput(QTextEdit):
    """Multiline composer: Enter inserts a newline; Ctrl+Enter sends."""

    send_requested = pyqtSignal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        is_enter = event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
        is_control_enter = bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
        if is_enter and is_control_enter:
            self.send_requested.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class ChatBubble(QWidget):
    """Compact, content-sized message bubble with bubble-local mouse actions."""

    left_clicked = pyqtSignal(dict)
    context_menu_requested = pyqtSignal(dict, object)

    def __init__(self, row: dict, parent=None):
        super().__init__(parent)
        self.row = dict(row)
        self._press_pos = None
        self._dragged = False
        outer = QHBoxLayout(self)
        # Keep incoming bubbles close to the left edge and outgoing bubbles
        # close to the right edge instead of wasting space in either gutter.
        outer.setContentsMargins(0, 1, 0, 1)
        outer.setSpacing(0)
        bubble = QFrame()
        self.bubble = bubble
        # The bubble is content-sized. Only very long text gets a bounded
        # width and wraps; short messages never inherit the row width.
        bubble.setMaximumWidth(560)
        bubble.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["ts"]))
        bubble.setToolTip(timestamp)
        outgoing = row["direction"] == "out"
        bubble.setStyleSheet(
            f"QFrame{{background:{'#FBE4D4' if outgoing else '#FFFFFF'};border:1px solid {'#F0D3C0' if outgoing else '#E5E0DA'};border-radius:14px;}}"
        )
        content = QVBoxLayout(bubble)
        content.setContentsMargins(10, 7, 10, 6)
        content.setSpacing(2)
        body = QLabel(("📎  " if row["kind"] == "file" else "") + row["body"])
        body.setWordWrap(True)
        body.setMaximumWidth(540)
        body.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.setStyleSheet("border:0;background:transparent;padding:1px")
        content.addWidget(body)
        if row["kind"] == "file":
            state = QLabel(row["status"])
            state.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
            state.setStyleSheet(f"color:{MUTED};font-size:11px;border:0;background:transparent;padding:1px")
            content.addWidget(state)
        if outgoing:
            outer.addStretch(1)
            outer.addWidget(bubble)
        else:
            outer.addWidget(bubble)
            outer.addStretch(1)
        for target in (bubble, *bubble.findChildren(QWidget)):
            target.setToolTip(timestamp)
            target.installEventFilter(self)
            target.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            target.customContextMenuRequested.connect(
                lambda pos, widget=target: self.context_menu_requested.emit(
                    self.row, widget.mapToGlobal(pos)
                )
            )

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
            self._press_pos = event.globalPosition().toPoint()
            self._dragged = False
        elif (
            event.type() == QEvent.Type.MouseMove
            and self._press_pos is not None
            and event.buttons() & Qt.MouseButton.LeftButton
        ):
            point = event.globalPosition().toPoint()
            if (point - self._press_pos).manhattanLength() > QApplication.startDragDistance():
                self._dragged = True
        elif event.type() == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton:
            point = event.globalPosition().toPoint()
            moved = self._press_pos is not None and (
                point - self._press_pos
            ).manhattanLength() > QApplication.startDragDistance()
            was_click = self._press_pos is not None and not self._dragged and not moved
            self._press_pos = None
            self._dragged = False
            if was_click and self.bubble.rect().contains(self.bubble.mapFromGlobal(point)):
                self.left_clicked.emit(self.row)
        return super().eventFilter(watched, event)


def configure_message_list(chat: QListWidget) -> None:
    """Make chat rows layout-only; message content is handled by its bubble."""
    chat.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    chat.setContentsMargins(0, 0, 0, 0)
    chat.setViewportMargins(0, 0, 0, 0)
    chat.setStyleSheet(
        "QListWidget#chatMessages { padding: 0; margin: 0; }"
        "QListWidget::item { padding: 0; margin: 0; border: 0; }"
        "QListWidget::item:selected { background: transparent; }"
    )


class Main(QMainWindow):
    def __init__(self, record, server):
        super().__init__()
        self.record = record
        self.priv = X25519PrivateKey.from_private_bytes(b64d(record["private"]))
        self.myid = record["public"]
        self.api = Api(server, self.priv)
        self.cfg = read_config()
        self.cursor = 0
        self.current = None
        self.active = {}
        self.pool = QThreadPool.globalInstance()
        self.pool.setMaxThreadCount(max(4, QThread.idealThreadCount()))
        self.setWindowTitle(f"P2PChat v{APP_VERSION} · {record['name']}")
        self.resize(1120, 760)
        root = QSplitter()
        left = QWidget()
        left.setObjectName("left")
        lv = QVBoxLayout(left)
        lv.setContentsMargins(16, 18, 16, 16)
        lv.setSpacing(12)
        top = QHBoxLayout()
        contacts_title = QLabel("Contacts")
        contacts_title.setObjectName("chatTitle")
        top.addWidget(contacts_title)
        lv.addLayout(top)
        self.contacts = QListWidget()
        self.contacts.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.contacts.customContextMenuRequested.connect(self.friend_menu)
        lv.addWidget(self.contacts, 1)
        friend_actions = QHBoxLayout()
        friend_actions.setSpacing(8)
        add = QPushButton("+ Add contact")
        add.setMinimumHeight(32)
        add.clicked.connect(self.add_friend)
        friend_actions.addWidget(add, 1)
        self.request_button = QPushButton("Friend requests")
        self.request_button.setMinimumHeight(32)
        self.request_button.clicked.connect(self.manage_requests)
        friend_actions.addWidget(self.request_button, 1)
        lv.addLayout(friend_actions)
        self.left_panel = left
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(20, 16, 20, 16)
        rv.setSpacing(10)
        head = QHBoxLayout()
        self.title = QLabel("Select a contact")
        self.title.setObjectName("chatTitle")
        head.addWidget(self.title, 1)
        self.collapse_button = QToolButton()
        self.collapse_button.setArrowType(Qt.ArrowType.LeftArrow)
        self.collapse_button.setToolTip("Collapse contacts")
        self.collapse_button.setFixedSize(30, 30)
        self.collapse_button.setCheckable(True)
        self.collapse_button.toggled.connect(self.toggle_sidebar)
        head.addWidget(self.collapse_button)
        rv.addLayout(head)
        self.chat = QListWidget()
        self.chat.setObjectName("chatMessages")
        self.chat.setSpacing(4)
        configure_message_list(self.chat)
        self.chat.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.chat.customContextMenuRequested.connect(self.message_menu)
        rv.addWidget(self.chat, 1)
        sendrow = QHBoxLayout()
        sendrow.setSpacing(6)
        self.input = ChatInput()
        self.input.setObjectName("chatInput")
        self.input.setMinimumHeight(42)
        self.input.setMaximumHeight(80)
        self.input.setFixedHeight(42)
        self.input.setPlaceholderText("Type a message (Enter for newline, Ctrl+Enter to send)")
        self.input.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.input.textChanged.connect(self.resize_input)
        self.input.send_requested.connect(self.send_text)
        sendrow.addWidget(self.input, 1)
        send = QPushButton("Send")
        send.setObjectName("primary")
        send.setMinimumHeight(32)
        send.clicked.connect(self.send_text)
        sendrow.addWidget(send)
        file_menu = QMenu(self)
        select_files = QAction("Choose files to send…", self)
        select_files.triggered.connect(self.choose_files)
        file_menu.addAction(select_files)
        self.file_menu_button = QToolButton()
        self.file_menu_button.setArrowType(Qt.ArrowType.DownArrow)
        self.file_menu_button.setToolTip("Send files (multiple selection; each file is end-to-end encrypted before upload)")
        self.file_menu_button.setMenu(file_menu)
        self.file_menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.file_menu_button.setFixedSize(28, 32)
        sendrow.addWidget(self.file_menu_button)
        rv.addLayout(sendrow)
        root.addWidget(left)
        root.addWidget(right)
        root.setSizes([320, 800])
        self.splitter = root
        self.setCentralWidget(root)
        self.contacts.currentItemChanged.connect(self.select_contact)
        self._refresh_contacts()
        self.update_request_button()
        self.poller = Poller(self.api, self.priv, self.cursor)
        self.poller.sig.message.connect(self.incoming)
        self.poller.sig.error.connect(self.show_error)
        self.poller.start()
        self.retry_pending_downloads()
        menu = self.menuBar().addMenu("Chat")
        copy_key = QAction("Copy my public key", self)
        copy_key.triggered.connect(lambda _checked=False: self.copy_text(self.myid))
        menu.addAction(copy_key)
        sync = QAction("Resync cloud records", self)
        sync.triggered.connect(self.resync)
        menu.addAction(sync)

    def closeEvent(self, e):
        self.poller.stop()
        self.poller.wait(3000)
        super().closeEvent(e)

    def toggle_sidebar(self, hidden):
        self.left_panel.setVisible(not hidden)
        if hidden:
            self.collapse_button.setArrowType(Qt.ArrowType.RightArrow)
            self.collapse_button.setToolTip("Expand contacts")
        else:
            self.collapse_button.setArrowType(Qt.ArrowType.LeftArrow)
            self.collapse_button.setToolTip("Collapse contacts")

    def copy_text(self, text):
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage("Copied to clipboard", 2500)

    def resize_input(self, _text=""):
        """Grow the composer with its content, up to the previous 80 px limit."""
        document = self.input.document()
        document.setTextWidth(max(1, self.input.viewport().width()))
        content_height = int(document.size().height()) + 14
        self.input.setFixedHeight(max(42, min(80, content_height)))

    def _refresh_contacts(self):
        self.contacts.clear()
        for name, pub in self.cfg.get("contacts", {}).items():
            it = QListWidgetItem(name)
            it.setData(Qt.ItemDataRole.UserRole, pub)
            self.contacts.addItem(it)

    def add_friend(self, _checked=False):
        d = QDialog(self)
        d.setWindowTitle("Add contact")
        v = QVBoxLayout(d)
        v.addWidget(QLabel("Display name"))
        name = QLineEdit()
        v.addWidget(name)
        v.addWidget(QLabel("Peer public key (43 characters; paste it)"))
        key = QLineEdit()
        v.addWidget(key)
        paste = QPushButton("Paste from clipboard")
        paste.clicked.connect(lambda _checked=False: key.setText(QGuiApplication.clipboard().text()))
        v.addWidget(paste)
        b = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        b.accepted.connect(d.accept)
        b.rejected.connect(d.reject)
        v.addWidget(b)
        if d.exec() != QDialog.DialogCode.Accepted:
            return
        pub = key.text().strip()
        try:
            if len(b64d(pub)) != 32:
                raise ValueError()
        except Exception:
            QMessageBox.warning(self, "Invalid public key", "Please make sure you pasted the complete public key")
            return
        alias = name.text().strip() or pub[:10]
        request_id = uuid.uuid4().hex
        self.save_message(pub, request_id, "out", "system", "Friend request sent", status="Waiting to send")
        cfg = read_config()
        cfg.setdefault("contacts", {})[alias] = pub
        write_config(cfg)
        self.cfg = cfg
        self._refresh_contacts()
        self.run_job(
            request_id,
            lambda _p: self.api.send(
                seal(
                    self.priv,
                    pub,
                    {"type": "friend_request", "alias": self.record["name"]},
                    request_id,
                )
            ),
        )

    def select_contact(self, item, *_):
        if not item:
            return
        self.current = item.data(Qt.ItemDataRole.UserRole)
        self.title.setText(item.text().splitlines()[0])
        self.render_chat()

    def render_chat(self):
        self.chat.clear()
        if not self.current:
            return
        with dbconn() as c:
            rows = c.execute(
                "SELECT * FROM messages WHERE identity=? AND peer=? ORDER BY ts,id",
                (self.myid, self.current),
            ).fetchall()
        for r in rows:
            if r["direction"] == "in":
                # Contacts are stored as alias -> public key; compare against values.
                accepted = r["peer"] in self.cfg.get("contacts", {}).values()
                if not accepted:
                    continue
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, dict(r))
            bubble = ChatBubble(dict(r))
            bubble.left_clicked.connect(self.message_clicked)
            bubble.context_menu_requested.connect(self.show_message_menu)
            item.setSizeHint(bubble.sizeHint())
            self.chat.addItem(item)
            self.chat.setItemWidget(item, bubble)
        self.chat.scrollToBottom()

    def save_message(
        self,
        peer,
        mid,
        direction,
        kind,
        body,
        ts=None,
        file_id=None,
        file_meta=None,
        path=None,
        status="ok",
    ):
        with dbconn() as c:
            c.execute(
                "INSERT OR IGNORE INTO messages(identity,peer,msg_id,direction,kind,body,ts,file_id,file_meta,local_path,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    self.myid,
                    peer,
                    mid,
                    direction,
                    kind,
                    body,
                    ts or time.time(),
                    file_id,
                    file_meta,
                    path,
                    status,
                ),
            )

    def incoming(self, body):
        """Keep slot exceptions visible instead of silently losing a received message."""
        try:
            self._process_incoming(body)
        except Exception as error:  # noqa: BLE001 - show GUI-side persistence/rendering failures
            self.show_error(f"Failed to process incoming message: {error}")

    def _process_incoming(self, b):
        sid = int(b.pop("_server_id", 0))
        sender = b.get("from")
        mid = b.get("msg_id")
        if not sender or not mid:
            return
        with dbconn() as c:
            already = c.execute(
                "SELECT 1 FROM messages WHERE identity=? AND msg_id=?", (self.myid, mid)
            ).fetchone()
        if already:
            self.cursor = max(self.cursor, sid)
            return
        if b.get("type") == "friend_request":
            with dbconn() as c:
                c.execute(
                    "INSERT OR IGNORE INTO friend_requests(identity,peer,alias,status,updated) VALUES(?,?,?,'pending',?)",
                    (self.myid, sender, b.get("alias") or sender[:10], time.time()),
                )
            self.cursor = max(self.cursor, sid)
            self.statusBar().showMessage("New friend request", 5000)
            self.update_request_button()
            return
        if b.get("type") == "text":
            self.save_message(sender, mid, "in", "text", b.get("text", ""), b.get("ts"))
        elif b.get("type") == "file":
            meta = b["file"]
            self.save_message(
                sender,
                mid,
                "in",
                "file",
                meta["name"],
                b.get("ts"),
                meta["file_id"],
                json.dumps(meta),
                status="Pending download",
            )
            self.download_incoming(sender, mid, meta)
        self.cursor = max(self.cursor, sid)
        if sender == self.current:
            self.render_chat()

    def download_incoming(self, peer, mid, meta):
        key = mid

        def task(progress):
            file_descriptor, temporary_name = tempfile.mkstemp(suffix=".enc")
            os.close(
                file_descriptor
            )  # Windows locks mkstemp files while the descriptor stays open.
            enc = Path(temporary_name)
            out = unique_download_path(DL, meta["name"])
            try:
                self.api.download(meta["file_id"], enc)
                tmp = out.with_name(out.name + ".part")
                decrypt_file(enc, tmp, b64d(meta["key"]), meta, progress)
                os.replace(tmp, out)
                return (str(out), meta["file_id"])
            finally:
                enc.unlink(missing_ok=True)

        self.run_job(key, task)

    def retry_pending_downloads(self):
        """Retry interrupted incoming file downloads after opening this identity."""
        with dbconn() as connection:
            rows = connection.execute(
                "SELECT msg_id,file_meta FROM messages "
                "WHERE identity=? AND direction='in' AND kind='file' "
                "AND local_path IS NULL AND file_meta IS NOT NULL",
                (self.myid,),
            ).fetchall()
        for row in rows:
            try:
                metadata = json.loads(row["file_meta"])
                self.download_incoming(metadata.get("from", ""), row["msg_id"], metadata)
            except Exception as error:  # noqa: BLE001 - report corrupt local metadata
                self.show_error(f"Unable to resume pending download: {error}")

    def send_text(self, _checked=False):
        text = self.input.toPlainText().strip()
        if not self.current or not text:
            return
        self.input.clear()
        mid = uuid.uuid4().hex
        peer = self.current
        self.save_message(peer, mid, "out", "text", text, status="Sending")
        self.render_chat()
        self.run_job(
            mid,
            lambda _p: self.api.send(seal(self.priv, peer, {"type": "text", "text": text}, mid)),
        )

    def choose_files(self, _checked=False):
        if not self.current:
            self.show_error("Please select a contact first")
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Choose files to send (multiple selection)",
            "",
            "All files (*.*)",
        )
        if not paths:
            return
        for path in paths:
            self.send_file(path)

    def send_file(self, path):
        """Encrypt and send one file in a background task."""
        peer = self.current
        if not peer:
            return
        path = str(Path(path).expanduser().resolve())
        name = Path(path).name
        mid = uuid.uuid4().hex
        self.save_message(peer, mid, "out", "file", name, path=path, status="Encrypting and sending")
        self.render_chat()

        def task(progress):
            key = os.urandom(32)
            fid = secrets.token_hex(16)
            fd, tmpname = tempfile.mkstemp(suffix=".enc")
            os.close(fd)
            tmp = Path(tmpname)
            try:
                sha = encrypt_file(path, tmp, key, progress)
                self.api.upload(peer, fid, tmp, progress)
                meta = {
                    "file_id": fid,
                    "name": name,
                    "size": Path(path).stat().st_size,
                    "sha256": sha,
                    "key": b64e(key),
                }
                result = self.api.send(seal(self.priv, peer, {"type": "file", "file": meta}, mid))
                return {**result, "meta": meta}
            finally:
                tmp.unlink(missing_ok=True)

        self.run_job(mid, task)

    def run_job(self, key, fn):
        job = Job(key, fn)
        job.sig.progress.connect(lambda k, p: self._progress(k, p))
        job.sig.done.connect(self.job_done)
        job.sig.failed.connect(self.job_failed)
        self.pool.start(job)

    def _progress(self, key, value):
        self.statusBar().showMessage(f"Task {key[:8]}: {value}%")

    def message_clicked(self, row):
        if row["kind"] == "file":
            self.save_as(row)
        else:
            self.copy_text(row["body"])

    def job_done(self, key, result):
        if key.startswith("save:"):
            self.statusBar().showMessage(f"File saved as: {Path(result).name}", 5000)
            return
        with dbconn() as c:
            row = c.execute(
                "SELECT * FROM messages WHERE identity=? AND msg_id=?", (self.myid, key)
            ).fetchone()
            if isinstance(result, tuple):
                path, fid = result
                c.execute(
                    "UPDATE messages SET local_path=?,status='Saved' WHERE identity=? AND msg_id=?",
                    (path, self.myid, key),
                )
            elif row:
                meta = result.get("meta") if isinstance(result, dict) else None
                c.execute(
                    "UPDATE messages SET status='Sent', file_id=COALESCE(?,file_id), file_meta=COALESCE(?,file_meta) WHERE identity=? AND msg_id=?",
                    (
                        meta.get("file_id") if meta else None,
                        json.dumps(meta) if meta else None,
                        self.myid,
                        key,
                    ),
                )
        if self.current:
            self.render_chat()

    def job_failed(self, key, error):
        if key.startswith("save:"):
            self.show_error("File save failed: " + error)
            return
        with dbconn() as c:
            c.execute(
                "UPDATE messages SET status=? WHERE identity=? AND msg_id=?",
                ("Failed: " + error[:140], self.myid, key),
            )
        self.show_error("Task failed: " + error)
        if self.current:
            self.render_chat()

    def show_error(self, text):
        self.statusBar().showMessage(text, 10000)

    def message_menu(self, pos):
        item = self.chat.itemAt(pos)
        if not item:
            return
        row = item.data(Qt.ItemDataRole.UserRole)
        self.show_message_menu(row, self.chat.mapToGlobal(pos))

    def show_message_menu(self, row, global_pos):
        menu = QMenu(self)
        copy = menu.addAction("Copy message/file name")
        save = None
        if row["kind"] == "file":
            save = menu.addAction("Save as…")
        act = menu.exec(global_pos)
        if act == copy:
            self.copy_text(row["body"])
        elif act == save:
            self.save_as(row)

    def friend_menu(self, pos):
        item = self.contacts.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        export_action = menu.addAction("Export chat history…")
        remove_action = menu.addAction("Remove contact")
        selected = menu.exec(self.contacts.mapToGlobal(pos))
        peer = item.data(Qt.ItemDataRole.UserRole)
        if selected == export_action:
            self.export_peer(peer)
        elif selected == remove_action:
            for alias, pub in list(self.cfg.get("contacts", {}).items()):
                if pub == peer:
                    self.cfg["contacts"].pop(alias, None)
            write_config(self.cfg)
            self._refresh_contacts()

    def update_request_button(self):
        with dbconn() as c:
            n = c.execute(
                "SELECT count(*) FROM friend_requests WHERE identity=? AND status='pending'",
                (self.myid,),
            ).fetchone()[0]
        self.request_button.setText(f"Requests · {n}" if n else "Requests")

    def manage_requests(self, _checked=False):
        dialog = QDialog(self)
        dialog.setWindowTitle("Friend request manager")
        dialog.resize(460, 360)
        layout = QVBoxLayout(dialog)
        request_list = QListWidget()
        layout.addWidget(request_list)

        def refresh():
            request_list.clear()
            with dbconn() as c:
                rows = c.execute(
                    "SELECT peer,alias FROM friend_requests WHERE identity=? AND status='pending' ORDER BY updated DESC",
                    (self.myid,),
                ).fetchall()
            for row in rows:
                item = QListWidgetItem(f"{row['alias']}\n{row['peer']}")
                item.setData(Qt.ItemDataRole.UserRole, (row["peer"], row["alias"]))
                request_list.addItem(item)
            self.update_request_button()

        actions = QHBoxLayout()
        accept = QPushButton("Accept")
        reject = QPushButton("Reject")
        actions.addWidget(accept)
        actions.addWidget(reject)
        layout.addLayout(actions)

        def decide(approved):
            item = request_list.currentItem()
            if not item:
                QMessageBox.information(dialog, "Notice", "Please select a request")
                return
            peer, alias = item.data(Qt.ItemDataRole.UserRole)
            if approved:
                self.cfg.setdefault("contacts", {})[alias] = peer
                write_config(self.cfg)
                self._refresh_contacts()
            with dbconn() as c:
                c.execute(
                    "UPDATE friend_requests SET status=?,updated=? WHERE identity=? AND peer=?",
                    ("accepted" if approved else "rejected", time.time(), self.myid, peer),
                )
            refresh()

        accept.clicked.connect(lambda _checked=False: decide(True))
        reject.clicked.connect(lambda _checked=False: decide(False))
        refresh()
        dialog.exec()

    def save_as(self, row):
        suggested = Path(row["body"].replace("\\", "/")).name or "received-file"
        path, _ = QFileDialog.getSaveFileName(self, "Save file as", suggested)
        if not path:
            return
        if row.get("local_path") and Path(row["local_path"]).is_file():
            source = Path(row["local_path"])
            destination = Path(path)
            self.run_job(
                "save:" + uuid.uuid4().hex,
                lambda progress: copy_file_with_progress(source, destination, progress),
            )
            return
        if row["direction"] == "out":
            self.show_error("The original file is unavailable, so it cannot be saved")
            return
        meta = json.loads(row["file_meta"] or "{}")
        if not meta:
            self.show_error("The file has not been downloaded and its metadata is unavailable")
            return
        self.run_job(
            "save:" + uuid.uuid4().hex,
            lambda progress: self._download_to(meta, Path(path), progress),
        )

    def _download_to(self, meta, path, progress):
        fd, tmpname = tempfile.mkstemp(suffix=".enc")
        os.close(fd)
        enc = Path(tmpname)
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.part")
        try:
            self.api.download(meta["file_id"], enc)
            decrypt_file(enc, tmp, b64d(meta["key"]), meta, progress)
            os.replace(tmp, path)
            return str(path)
        finally:
            enc.unlink(missing_ok=True)
            tmp.unlink(missing_ok=True)

    def export(self):
        if not self.current:
            QMessageBox.information(self, "Export", "Select a contact first")
            return
        self.export_peer(self.current)

    def export_peer(self, peer):
        path, _ = QFileDialog.getSaveFileName(self, "Export chat history", "chat.txt", "Text files (*.txt)")
        if not path:
            return
        with dbconn() as c:
            rows = c.execute(
                "SELECT * FROM messages WHERE identity=? AND peer=? ORDER BY ts,id",
                (self.myid, peer),
            ).fetchall()
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(
                    f"{time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(r['ts']))} {'Me' if r['direction']=='out' else 'Peer'}:{r['body']}\n"
                )
        self.statusBar().showMessage("Chat history exported", 3000)

    def resync(self, _checked=False):
        self.poller.cursor = 0
        self.cursor = 0
        self.statusBar().showMessage("Syncing history from the server…", 4000)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    login = Login()
    if login.exec() != QDialog.DialogCode.Accepted:
        return 0
    rec = login.record()
    win = Main(rec, login.cfg["server"])
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
