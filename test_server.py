"""Load/integration test for the standalone P2PChat relay.

Examples:
    python test_server.py
    python test_server.py --server https://chat.example.com
    python test_server.py --users 100 --workers 12

The test creates ephemeral identities in memory, sends one encrypted text and one
random encrypted file per user, verifies end-to-end decryption and file hashes,
checks retained-history behavior and recipient-only downloads, then removes its
own server-side test records. Dependencies: requests, cryptography.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import secrets
import socket
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# These values must remain byte-for-byte compatible with client.py/server.py.
CHUNK_SIZE = 1024 * 1024
MESSAGE_INFO = b"p2pchat/msg/v1"
FILE_CHUNK_INFO = b"p2pchat/file-chunk/v1"
MESSAGE_AAD = b"p2pchat|msg|v1"
FILE_CHUNK_AAD = b"p2pchat|file-chunk|v1"
MAX_FAILURES_TO_PRINT = 20


def encode_base64url(value: bytes) -> str:
    """Encode bytes as unpadded URL-safe Base64."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value: str) -> bytes:
    """Decode URL-safe Base64 with or without padding."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def raw_public_key(key: X25519PrivateKey | X25519PublicKey) -> bytes:
    """Return the raw 32-byte X25519 public key."""
    public_key = key.public_key() if isinstance(key, X25519PrivateKey) else key
    return public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def public_identity(private_key: X25519PrivateKey) -> str:
    """Represent an identity by its public key, matching the production client."""
    return encode_base64url(raw_public_key(private_key))


def derive_key(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    """Derive an AES-256 key using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def message_aad(recipient_id: str, message_id: str, sender_id: str) -> bytes:
    """Bind ciphertext authentication to sender, recipient, and message ID."""
    return b"|".join(
        (
            MESSAGE_AAD,
            recipient_id.encode("ascii"),
            message_id.encode("ascii"),
            sender_id.encode("ascii"),
        )
    )


def encrypt_message(
    sender_private_key: X25519PrivateKey,
    recipient_id: str,
    payload: dict[str, Any],
    message_id: str | None = None,
) -> dict[str, Any]:
    """Create an E2E-encrypted envelope compatible with client.py."""
    sender_id = public_identity(sender_private_key)
    message_id = message_id or uuid.uuid4().hex
    salt = os.urandom(16)
    nonce = os.urandom(12)
    recipient_public_key = X25519PublicKey.from_public_bytes(decode_base64url(recipient_id))
    shared_secret = sender_private_key.exchange(recipient_public_key)
    encryption_key = derive_key(shared_secret, salt, MESSAGE_INFO)
    message_body = {
        "v": 1,
        "msg_id": message_id,
        "from": sender_id,
        "to": recipient_id,
        "ts": time.time(),
        **payload,
    }
    plaintext = json.dumps(
        message_body,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = AESGCM(encryption_key).encrypt(
        nonce,
        plaintext,
        message_aad(recipient_id, message_id, sender_id),
    )
    return {
        "v": 1,
        "msg_id": message_id,
        "from": sender_id,
        "to": recipient_id,
        "salt": encode_base64url(salt),
        "nonce": encode_base64url(nonce),
        "ct": encode_base64url(ciphertext),
    }


def decrypt_message(
    recipient_private_key: X25519PrivateKey,
    envelope: dict[str, Any],
) -> dict[str, Any]:
    """Decrypt one envelope and independently validate authenticated fields."""
    sender_id = envelope["from"]
    recipient_id = envelope["to"]
    message_id = envelope["msg_id"]
    sender_public_key = X25519PublicKey.from_public_bytes(decode_base64url(sender_id))
    shared_secret = recipient_private_key.exchange(sender_public_key)
    encryption_key = derive_key(
        shared_secret,
        decode_base64url(envelope["salt"]),
        MESSAGE_INFO,
    )
    plaintext = AESGCM(encryption_key).decrypt(
        decode_base64url(envelope["nonce"]),
        decode_base64url(envelope["ct"]),
        message_aad(recipient_id, message_id, sender_id),
    )
    body = json.loads(plaintext.decode("utf-8"))
    if (
        body.get("from") != sender_id
        or body.get("to") != recipient_id
        or body.get("msg_id") != message_id
    ):
        raise ValueError("decrypted message fields do not match the envelope")
    return body


def derive_file_chunk_key(file_key: bytes, chunk_index: int) -> bytes:
    """Derive a distinct key for each file chunk."""
    return derive_key(
        file_key,
        b"",
        FILE_CHUNK_INFO + chunk_index.to_bytes(8, "big"),
    )


def encrypt_file(source_path: Path, encrypted_path: Path, file_key: bytes) -> str:
    """Encrypt a file in authenticated 1 MiB chunks and return its SHA-256."""
    digest = hashlib.sha256()
    chunk_index = 0
    with source_path.open("rb") as source, encrypted_path.open("wb") as encrypted:
        while True:
            plaintext_chunk = source.read(CHUNK_SIZE)
            digest.update(plaintext_chunk)
            chunk_nonce = chunk_index.to_bytes(12, "big")
            ciphertext_chunk = AESGCM(derive_file_chunk_key(file_key, chunk_index)).encrypt(
                chunk_nonce, plaintext_chunk, FILE_CHUNK_AAD
            )
            encrypted.write(len(ciphertext_chunk).to_bytes(4, "big"))
            encrypted.write(ciphertext_chunk)
            chunk_index += 1
            if len(plaintext_chunk) < CHUNK_SIZE:
                break
    return digest.hexdigest()


def decrypt_file(
    encrypted_path: Path,
    restored_path: Path,
    file_key: bytes,
    expected_sha256: str,
) -> int:
    """Decrypt all chunks, validate the digest, and return restored byte count."""
    digest = hashlib.sha256()
    restored_size = 0
    chunk_index = 0
    with encrypted_path.open("rb") as encrypted, restored_path.open("wb") as restored:
        while True:
            length_header = encrypted.read(4)
            if not length_header:
                break
            if len(length_header) != 4:
                raise ValueError("truncated file chunk length")
            ciphertext_length = int.from_bytes(length_header, "big")
            if not 16 <= ciphertext_length <= CHUNK_SIZE + 16:
                raise ValueError(f"invalid ciphertext chunk length: {ciphertext_length}")
            ciphertext_chunk = encrypted.read(ciphertext_length)
            if len(ciphertext_chunk) != ciphertext_length:
                raise ValueError("truncated encrypted file chunk")
            plaintext_chunk = AESGCM(derive_file_chunk_key(file_key, chunk_index)).decrypt(
                chunk_index.to_bytes(12, "big"),
                ciphertext_chunk,
                FILE_CHUNK_AAD,
            )
            restored.write(plaintext_chunk)
            digest.update(plaintext_chunk)
            restored_size += len(plaintext_chunk)
            chunk_index += 1
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        restored_path.unlink(missing_ok=True)
        raise ValueError("restored file SHA-256 does not match")
    return restored_size


@dataclass(frozen=True)
class TestUser:
    """Ephemeral test identity that exists only in memory."""

    index: int
    private_key: X25519PrivateKey
    public_id: str


@dataclass
class SentRecord:
    """Expected plaintext and IDs for one sender/receiver test pair."""

    sender_index: int
    recipient_index: int
    text_message_id: str
    file_message_id: str
    file_id: str
    expected_text: str
    source_path: Path
    expected_size: int
    expected_sha256: str


class RelayApi:
    """Small authenticated HTTP client used by this test script."""

    def __init__(self, server_url: str, private_key: X25519PrivateKey):
        self.server_url = server_url.rstrip("/")
        self.private_key = private_key
        self.identity_id = public_identity(private_key)
        self._cached_server_public_key: bytes | None = None

    def authentication_params(self) -> dict[str, str]:
        """Build the server's timestamped DH-HMAC proof for a single request."""
        if self._cached_server_public_key is None:
            response = requests.get(
                f"{self.server_url}/api/server-key",
                timeout=15,
            )
            response.raise_for_status()
            self._cached_server_public_key = decode_base64url(response.json()["public_key"])
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        shared_secret = self.private_key.exchange(
            X25519PublicKey.from_public_bytes(self._cached_server_public_key)
        )
        proof = hmac.new(
            shared_secret,
            f"{self.identity_id}:{timestamp}:{nonce}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        return {
            "identity": self.identity_id,
            "ts": timestamp,
            "nonce": nonce,
            "proof": encode_base64url(proof),
        }

    def post(self, endpoint: str, data: dict[str, str] | None = None) -> dict[str, Any]:
        """POST URL-encoded data with per-request authentication fields."""
        form_data = self.authentication_params()
        form_data.update(data or {})
        response = requests.post(
            self.server_url + endpoint,
            data=form_data,
            timeout=60,
        )
        response.raise_for_status()
        return response.json()

    def send_envelope(self, envelope: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/send", {"envelope": json.dumps(envelope)})

    def fetch(self, after_id: int = 0) -> list[dict[str, Any]]:
        response = self.post(
            "/api/fetch",
            {"after_id": str(after_id), "limit": "300"},
        )
        return response["messages"]

    def acknowledge(self, message_ids: list[str]) -> None:
        self.post("/api/ack", {"msg_ids": json.dumps(message_ids)})

    def upload_encrypted_file(
        self,
        recipient_id: str,
        file_id: str,
        encrypted_path: Path,
    ) -> None:
        """Stream ciphertext from disk; never buffer the whole file in RAM."""
        with encrypted_path.open("rb") as encrypted_file:
            response = requests.put(
                f"{self.server_url}/api/upload/{recipient_id}/{file_id}",
                params=self.authentication_params(),
                data=encrypted_file,
                timeout=(15, 900),
            )
        response.raise_for_status()

    def download_encrypted_file(self, file_id: str, destination: Path) -> None:
        """Stream an authorized encrypted-file download to disk."""
        response = requests.get(
            f"{self.server_url}/api/file/{file_id}",
            params=self.authentication_params(),
            stream=True,
            timeout=(15, 900),
        )
        response.raise_for_status()
        with destination.open("wb") as output_file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    output_file.write(chunk)

    def delete_test_records(
        self,
        message_ids: list[str],
        file_ids: list[str],
    ) -> None:
        self.post(
            "/api/delete",
            {
                "msg_ids": json.dumps(message_ids),
                "file_ids": json.dumps(file_ids),
            },
        )


class TestRun:
    """Run a 100-user concurrent send/receive verification against a relay."""

    def __init__(self, server_url: str, user_count: int, worker_count: int):
        self.server_url = server_url.rstrip("/")
        self.user_count = user_count
        self.worker_count = worker_count
        self.users: list[TestUser] = []
        self.apis: list[RelayApi] = []
        self.sent_records: list[SentRecord] = []
        self.failures: list[str] = []
        self.cleanup_failures: list[str] = []
        self.total_upload_bytes = 0
        self.total_download_bytes = 0
        self._stats_lock = threading.Lock()

    def check_server(self) -> None:
        """Fail early if this URL is not the matching standalone relay."""
        response = requests.get(self.server_url + "/", timeout=10)
        response.raise_for_status()
        info = response.json()
        if info.get("name") != "p2pchat-standalone":
            raise RuntimeError(
                "The target does not identify itself as p2pchat-standalone "
                f"(server info: {info!r}). Check --server."
            )

    def create_users(self) -> None:
        """Generate isolated identities; never writes keys into client_data."""
        self.users = []
        for index in range(self.user_count):
            private_key = X25519PrivateKey.generate()
            self.users.append(TestUser(index, private_key, public_identity(private_key)))
        self.apis = [RelayApi(self.server_url, user.private_key) for user in self.users]

    def random_file_size(self, sender_index: int, maximum_bytes: int) -> int:
        """Mix random lengths with chunk-edge cases so both code paths are tested."""
        if sender_index % 10 == 0:
            return (0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1)[(sender_index // 10) % 5]
        return random.randint(1, maximum_bytes)

    def send_from_user(
        self,
        sender_index: int,
        temporary_dir: Path,
        maximum_bytes: int,
    ) -> SentRecord:
        """Send a text and a random file to the next user in a ring."""
        recipient_index = (sender_index + 1) % self.user_count
        sender = self.users[sender_index]
        recipient = self.users[recipient_index]
        api = self.apis[sender_index]
        expected_text = f"P2PChat load test · sender={sender_index} · {uuid.uuid4().hex}"

        text_envelope = encrypt_message(
            sender.private_key,
            recipient.public_id,
            {"type": "text", "text": expected_text},
        )
        api.send_envelope(text_envelope)

        file_size = self.random_file_size(sender_index, maximum_bytes)
        source_path = temporary_dir / f"user-{sender_index:03d}.random"
        encrypted_path = temporary_dir / f"user-{sender_index:03d}.encrypted"
        source_path.write_bytes(os.urandom(file_size))
        file_key = os.urandom(32)
        expected_sha256 = encrypt_file(source_path, encrypted_path, file_key)
        file_id = secrets.token_hex(16)
        api.upload_encrypted_file(recipient.public_id, file_id, encrypted_path)

        file_metadata = {
            "file_id": file_id,
            "name": source_path.name,
            "size": file_size,
            "sha256": expected_sha256,
            "key": encode_base64url(file_key),
        }
        file_envelope = encrypt_message(
            sender.private_key,
            recipient.public_id,
            {"type": "file", "file": file_metadata},
        )
        api.send_envelope(file_envelope)
        with self._stats_lock:
            self.total_upload_bytes += encrypted_path.stat().st_size

        return SentRecord(
            sender_index=sender_index,
            recipient_index=recipient_index,
            text_message_id=text_envelope["msg_id"],
            file_message_id=file_envelope["msg_id"],
            file_id=file_id,
            expected_text=expected_text,
            source_path=source_path,
            expected_size=file_size,
            expected_sha256=expected_sha256,
        )

    def send_all(self, temporary_dir: Path, maximum_bytes: int) -> None:
        """Send concurrently, collecting each worker's failure without aborting."""
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=self.worker_count) as executor:
            futures = {
                executor.submit(
                    self.send_from_user,
                    sender_index,
                    temporary_dir,
                    maximum_bytes,
                ): sender_index
                for sender_index in range(self.user_count)
            }
            for future in as_completed(futures):
                sender_index = futures[future]
                try:
                    self.sent_records.append(future.result())
                except Exception as error:  # noqa: BLE001 - report all independent failures
                    self.failures.append(f"sender {sender_index}: send failed: {error}")
        self.send_duration = time.perf_counter() - started

    def verify_recipient(self, recipient_index: int, temporary_dir: Path) -> tuple[int, int]:
        """Fetch, decrypt, verify, and acknowledge one recipient's messages/files."""
        api = self.apis[recipient_index]
        records = [
            record for record in self.sent_records if record.recipient_index == recipient_index
        ]
        expected_ids = {record.text_message_id for record in records} | {
            record.file_message_id for record in records
        }
        messages = api.fetch(after_id=0)
        actual_ids = {item["envelope"].get("msg_id") for item in messages if item.get("envelope")}
        if actual_ids != expected_ids:
            raise AssertionError(
                f"recipient {recipient_index} expected {len(expected_ids)} test "
                f"messages but received {len(actual_ids)}; unexpected="
                f"{len(actual_ids - expected_ids)}, missing={len(expected_ids - actual_ids)}"
            )

        expected_by_id = {record.text_message_id: (record, "text") for record in records}
        expected_by_id.update({record.file_message_id: (record, "file") for record in records})
        file_checks = 0
        for item in messages:
            envelope = item["envelope"]
            body = decrypt_message(self.users[recipient_index].private_key, envelope)
            record, message_kind = expected_by_id[body["msg_id"]]
            expected_sender_id = self.users[record.sender_index].public_id
            if body.get("from") != expected_sender_id:
                raise AssertionError("sender identity mismatch after decryption")
            if body.get("type") != message_kind:
                raise AssertionError(
                    f"message type mismatch: expected {message_kind!r}, got {body.get('type')!r}"
                )
            if message_kind == "text":
                if body.get("text") != record.expected_text:
                    raise AssertionError("decrypted text did not match the sent text")
                continue

            metadata = body["file"]
            if metadata.get("file_id") != record.file_id:
                raise AssertionError("file ID mismatch after decryption")
            encrypted_download = temporary_dir / f"received-{record.file_id}.enc"
            restored_path = temporary_dir / f"received-{record.file_id}.plain"
            api.download_encrypted_file(record.file_id, encrypted_download)
            file_key = decode_base64url(metadata["key"])
            restored_size = decrypt_file(
                encrypted_download,
                restored_path,
                file_key,
                metadata["sha256"],
            )
            if restored_size != record.expected_size:
                raise AssertionError(
                    f"file size mismatch: expected {record.expected_size}, got {restored_size}"
                )
            if restored_path.read_bytes() != record.source_path.read_bytes():
                raise AssertionError("restored random file does not match the source file")
            with self._stats_lock:
                self.total_download_bytes += encrypted_download.stat().st_size
            file_checks += 1

        api.acknowledge(sorted(expected_ids))
        # ack is deliberately non-destructive, so the exact same page must remain syncable.
        retained_ids = {item["envelope"].get("msg_id") for item in api.fetch(after_id=0)}
        if retained_ids != expected_ids:
            raise AssertionError("ack deleted or changed retained server history")
        return len(expected_ids), file_checks

    def verify_all_recipients(self, temporary_dir: Path) -> tuple[int, int]:
        """Verify recipients concurrently and preserve a detailed failure report."""
        verified_messages = 0
        verified_files = 0
        with ThreadPoolExecutor(max_workers=self.worker_count) as executor:
            futures = {
                executor.submit(self.verify_recipient, index, temporary_dir): index
                for index in range(self.user_count)
            }
            for future in as_completed(futures):
                recipient_index = futures[future]
                try:
                    message_count, file_count = future.result()
                    verified_messages += message_count
                    verified_files += file_count
                except Exception as error:  # noqa: BLE001 - continue verifying other users
                    self.failures.append(f"recipient {recipient_index}: verify failed: {error}")
        return verified_messages, verified_files

    def verify_access_control(self) -> bool:
        """A non-recipient must not download another user's file."""
        if not self.sent_records:
            return False
        record = self.sent_records[0]
        unauthorized_index = (record.recipient_index + 1) % self.user_count
        unauthorized_api = self.apis[unauthorized_index]
        response = requests.get(
            f"{self.server_url}/api/file/{record.file_id}",
            params=unauthorized_api.authentication_params(),
            timeout=30,
        )
        if response.status_code not in (403, 404):
            raise AssertionError(
                f"unauthorized file download returned HTTP {response.status_code}, expected 403/404"
            )
        return True

    def cleanup(self) -> None:
        """Remove only records created by this test run; preserve unrelated server data."""
        for record in self.sent_records:
            try:
                recipient_api = self.apis[record.recipient_index]
                recipient_api.delete_test_records(
                    [record.text_message_id, record.file_message_id],
                    [record.file_id],
                )
            except Exception as error:  # noqa: BLE001 - cleanup failures are reported
                self.cleanup_failures.append(
                    f"file/message {record.file_id}: cleanup failed: {error}"
                )

    def print_report(
        self,
        elapsed_seconds: float,
        verified_messages: int,
        verified_files: int,
        access_control_passed: bool,
    ) -> None:
        """Print a plain-text summary suitable for logs and support requests."""
        print("\n" + "=" * 72)
        print("P2PChat relay test report")
        print("=" * 72)
        print(f"Target server          : {self.server_url}")
        print(f"Ephemeral users         : {self.user_count}")
        print(f"Concurrent workers      : {self.worker_count}")
        print(f"Text messages verified  : {verified_messages - verified_files}")
        print(f"Random files verified   : {verified_files}")
        print(f"Encrypted bytes uploaded: {self.total_upload_bytes:,}")
        print(f"Encrypted bytes received: {self.total_download_bytes:,}")
        print(f"Send phase              : {getattr(self, 'send_duration', 0.0):.2f} s")
        print(f"Total elapsed           : {elapsed_seconds:.2f} s")
        print(f"Recipient access control: {'PASS' if access_control_passed else 'NOT RUN'}")
        print("History retained after ack: checked for each recipient")
        print(f"Test operation failures : {len(self.failures)}")
        print(f"Cleanup failures        : {len(self.cleanup_failures)}")
        for failure in (self.failures + self.cleanup_failures)[:MAX_FAILURES_TO_PRINT]:
            print(f"  - {failure}")
        if len(self.failures) + len(self.cleanup_failures) > MAX_FAILURES_TO_PRINT:
            print("  ... more failures omitted")
        if self.failures or self.cleanup_failures:
            print("RESULT                  : FAIL")
        else:
            print("RESULT                  : PASS")
        print("=" * 72)


def parse_arguments() -> argparse.Namespace:
    """Parse target URL and bounded stress-test settings."""
    parser = argparse.ArgumentParser(description="Stress-test a P2PChat relay server")
    parser.add_argument(
        "--server",
        default=os.environ.get("P2PCHAT_TEST_SERVER", "http://127.0.0.1:8000"),
        help="Relay URL (default: P2PCHAT_TEST_SERVER or localhost:8000)",
    )
    parser.add_argument(
        "--users",
        type=int,
        default=100,
        help="Number of ephemeral identities (default: 100)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=12,
        help="Maximum simultaneous HTTP test jobs (default: 12)",
    )
    parser.add_argument(
        "--max-file-kib",
        type=int,
        default=512,
        help="Upper random file size in KiB (default: 512); chunk edges are added separately",
    )
    parser.add_argument(
        "--keep-test-data",
        action="store_true",
        help="Do not delete test messages/files from the relay after the run",
    )
    options = parser.parse_args()
    if options.users < 2:
        parser.error("--users must be at least 2")
    if options.workers < 1:
        parser.error("--workers must be at least 1")
    if options.max_file_kib < 1:
        parser.error("--max-file-kib must be positive")
    return options


def main() -> int:
    options = parse_arguments()
    test_run = TestRun(
        options.server,
        options.users,
        min(options.workers, options.users),
    )
    started_at = time.perf_counter()
    verified_messages = 0
    verified_files = 0
    access_control_passed = False
    server_available = False

    try:
        test_run.check_server()
        server_available = True
        print(f"[1/5] Server reachable: {options.server}")
        test_run.create_users()
        print(f"[2/5] Generated {options.users} ephemeral users")

        with tempfile.TemporaryDirectory(prefix="p2pchat-server-test-") as temp_name:
            temporary_dir = Path(temp_name)
            maximum_file_bytes = options.max_file_kib * 1024
            print(
                f"[3/5] Sending encrypted text + random files "
                f"({test_run.worker_count} concurrent workers)…"
            )
            test_run.send_all(temporary_dir, maximum_file_bytes)
            print("[4/5] Fetching, decrypting, hash-checking, and testing retained history…")
            verified_messages, verified_files = test_run.verify_all_recipients(temporary_dir)
            try:
                access_control_passed = test_run.verify_access_control()
            except Exception as error:  # noqa: BLE001 - report access-control failure
                test_run.failures.append(f"access control: {error}")
            if not options.keep_test_data:
                print("[5/5] Removing this run's test messages and encrypted files…")
                test_run.cleanup()
            else:
                print("[5/5] Keeping test records on the relay (--keep-test-data)")
    except Exception as error:  # noqa: BLE001 - include startup errors in report
        test_run.failures.append(f"test setup/runtime: {error}")
        if not server_available:
            print(f"Unable to run tests: {error}", file=sys.stderr)
    finally:
        elapsed_seconds = time.perf_counter() - started_at
        test_run.print_report(
            elapsed_seconds,
            verified_messages,
            verified_files,
            access_control_passed,
        )

    return 1 if test_run.failures or test_run.cleanup_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
