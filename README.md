# 🔒 P2PChat Standalone

> **v1.1 · Simple · Private · Self-hosted**  
> An end-to-end encrypted chat application built with Python, FastAPI, PyQt6, and modern cryptography.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Relay-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)

📌 Project: <https://github.com/wangyifan349/p2pchat_standalone_en>

## ✨ Overview

P2PChat Standalone is a private chat application with a server you can deploy yourself:

- 💬 Desktop GUI chat
- 🔐 End-to-end encrypted messages
- 📁 Encrypted file transfer
- ⚡ Background threads handle large files without blocking the interface
- 🌐 FastAPI + SQLite WAL relay service
- 🧩 Single-file client and single-file server for easy understanding and deployment

The server only authenticates, relays, and stores ciphertext; message bodies and file plaintext are encrypted and decrypted on clients.

## 🚀 Quick start

### 📋 One-step copy: download, install, and start the server

A virtual environment is not required; copy the complete command below:

```bash
git clone https://github.com/wangyifan349/p2pchat_standalone_en.git && cd p2pchat_standalone_en && python3 -m pip install PyQt6 cryptography requests fastapi uvicorn python-multipart && python3 server.py
```

Default server address: `http://127.0.0.1:8000`

After the server starts, open another terminal, enter the project directory, and start the client:

```bash
cd p2pchat_standalone_en && python3 client.py
```

Windows PowerShell:

```powershell
cd p2pchat_standalone_en; py -m pip install PyQt6 cryptography requests fastapi uvicorn python-multipart; py server.py
```

Start the client in another terminal:

```powershell
cd p2pchat_standalone_en; py client.py
```

First use:

1. Create a local identity.
2. Send your public key securely to your friend.
3. Add the friend and enter the friend's public key.
4. Start chatting after the other person accepts the friend request.

## 🧠 Core principles

### Message encryption flow

```text
Sender private key + recipient public key
                 │
                 ▼
              X25519
                 │
                 ▼
       HKDF-SHA256 key derivation
                 │
                 ▼
          AES-256-GCM encryption
                 │
                 ▼
       Server stores ciphertext envelope
```

- Each message uses a random salt and nonce.
- AAD binds the sender, recipient, and message ID to prevent tampering and misdelivery.
- Private keys remain on the client and are never uploaded to the server.
- Files are encrypted in chunks on the client, then uploaded as a stream.
- The recipient decrypts after downloading and verifies integrity with SHA-256.

### What can the server see?

The server can see:

- 👤 Sender and recipient public-key identities
- 🕒 Timestamps, message IDs, and ciphertext sizes
- 📦 Encrypted messages and file ciphertext

The server cannot directly see:

- ✅ Message bodies
- ✅ File plaintext contents
- ✅ File encryption keys

⚠️ E2EE does not hide communication metadata. The server may still know who communicates with whom, when they communicate, and how much data is transferred.

## ⚡ Concurrency and large files

- GUI encryption, upload, download, decryption, and Save As operations use the Qt thread pool.
- The server uses FastAPI, SQLite WAL, and streaming file uploads.
- Files are not loaded into memory all at once.
- Multiple file tasks can run in parallel while the chat interface remains responsive.

## 🌐 Public deployment

Recommended:

```text
Client ── HTTPS ──> Nginx / Caddy ──> server.py
```

Run locally:

```bash
python3 server.py
```

Set listener parameters:

```bash
P2PCHAT_HOST=127.0.0.1 P2PCHAT_PORT=8000 python3 server.py
```

HTTPS is required for public use; direct exposure of ordinary HTTP is not recommended.

Common environment variables:

| Variable | Default | Purpose |
|---|---:|---|
| `P2PCHAT_HOST` | `127.0.0.1` | Listen address |
| `P2PCHAT_PORT` | `8000` | Listen port |
| `P2PCHAT_SERVER_DATA` | `./server_data` | Server data directory |
| `P2PCHAT_THREAD_TOKENS` | `100` | Background-thread concurrency tokens |
| `P2PCHAT_SQLITE_SYNCHRONOUS` | `FULL` | SQLite durability mode |

## 🗂️ Data directories

Created automatically at runtime:

```text
client_data/       # Client identities, chat history, and downloaded files
server_data/       # Server key, database, and encrypted files
```

Do not commit these directories to GitHub. Protect these in particular:

- `client_data/identities/`
- `server_data/server-key.json`
- `server_data/relay.sqlite3`

## 🧪 Development tests

When the development directory includes the test files, run:

```bash
python3 -m py_compile client.py server.py test_client.py test_e2ee.py test_server.py
python3 -m unittest discover -v
```

## 🧩 Optional: compile a Windows `.pyd`

For this Qt project, first confirm that source-mode execution works before compiling with Cython. Compilation applies only to the client; the server continues to use `server.py`.

Install build tools:

```bash
python3 -m pip install cython setuptools
```

Compile:

```bash
python setup.py build_ext --inplace
```

After a successful Windows build, the project directory will contain a file matching the Python version and architecture, for example:

```text
client.cp314-win_amd64.pyd
```

Use the compiled client:

```bash
python3 start_client.py
```

`start_client.py` prefers a `.pyd` in the same directory and automatically falls back to `client.py` when none is found, which is useful for development and troubleshooting. Qt runtime dependencies must still be installed; the `.pyd` does not bundle PyQt6.

⚠️ A `.pyd` is not portable: it normally works only with the Python major version, architecture, and Windows environment used for compilation. After changing Python versions, run the build command again. Source mode remains available with `python3 client.py`.

Concurrent relay test:

```bash
python3 test_server.py --server http://127.0.0.1:8000 --users 100 --workers 12
```

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0-only (AGPL-3.0-only)**; see [LICENSE](./LICENSE).

If you modify this project and provide it to users over a network, AGPL-3.0 requires you to provide the corresponding source code to those users. You are welcome to use, modify, and contribute, but please retain the license and copyright notices.

## 🤝 Contributing

Issues and pull requests are welcome. For changes involving cryptography, authentication, network protocols, or data security, please also add tests and a security note.
