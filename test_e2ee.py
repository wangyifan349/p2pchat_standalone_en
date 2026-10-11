"""Protocol-level E2EE regression tests.

These tests intentionally inspect only the relay-visible envelope.  They verify
that the plaintext is absent, the intended recipient can decrypt it, and basic
relay tampering or misdelivery is rejected by the client.
"""

from __future__ import annotations

import copy
import json
import unittest

from cryptography.exceptions import InvalidTag

from client import X25519PrivateKey, b64d, b64e, ident, open_envelope, seal


class E2EEProtocolTests(unittest.TestCase):
    def test_relay_visible_message_contains_no_plaintext(self):
        sender = X25519PrivateKey.generate()
        recipient = X25519PrivateKey.generate()
        secret = "visible only to sender and recipient · secret payload"

        envelope = seal(sender, ident(recipient), {"type": "text", "text": secret})
        relay_view = json.dumps(envelope, ensure_ascii=False)

        self.assertNotIn(secret, relay_view)
        self.assertEqual(open_envelope(recipient, envelope)["text"], secret)

    def test_tampering_and_misdirection_are_rejected(self):
        sender = X25519PrivateKey.generate()
        recipient = X25519PrivateKey.generate()
        other_recipient = X25519PrivateKey.generate()
        envelope = seal(sender, ident(recipient), {"type": "text", "text": "hello"})

        tampered = copy.deepcopy(envelope)
        ciphertext = bytearray(b64d(tampered["ct"]))
        ciphertext[0] ^= 1
        tampered["ct"] = b64e(bytes(ciphertext))
        with self.assertRaises(InvalidTag):
            open_envelope(recipient, tampered)

        with self.assertRaises(ValueError):
            open_envelope(other_recipient, envelope)

        wrong_version = copy.deepcopy(envelope)
        wrong_version["v"] = 2
        with self.assertRaises(ValueError):
            open_envelope(recipient, wrong_version)

    def test_payload_cannot_override_authenticated_envelope_fields(self):
        sender = X25519PrivateKey.generate()
        recipient = X25519PrivateKey.generate()
        envelope = seal(
            sender,
            ident(recipient),
            {"type": "text", "text": "hello", "from": "spoofed", "v": 99},
        )
        body = open_envelope(recipient, envelope)
        self.assertEqual(body["from"], ident(sender))
        self.assertEqual(body["v"], 1)


if __name__ == "__main__":
    unittest.main()
