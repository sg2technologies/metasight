"""
AES encryption for DataSource credentials stored in `encrypted_config`.

Format (versioned so existing ciphertexts keep decrypting after this upgrade):

  v2 (current, written by encrypt()):
      base64( MAGIC(4) || nonce(12) || AES-256-GCM(ciphertext || 16-byte tag) )
    AES-GCM is an AEAD cipher — tampering with the stored blob (a compromised
    DB row, a corrupted backup, a malicious edit) is detected and raises on
    decrypt, instead of silently producing corrupted plaintext.

  v1 (legacy, decrypt-only):
      base64( iv(16) || AES-256-CFB(ciphertext) )
    CFB is an unauthenticated stream-cipher mode — bit-flips in the ciphertext
    silently corrupt the decrypted plaintext with no integrity check. Values
    already encrypted this way keep decrypting correctly; the next time a
    DataSource's config is saved it gets re-encrypted under v2.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from app.core.config import settings

_MAGIC = b"MSG1"  # "MetaSight GCM v1" ciphertext-format marker
_NONCE_LEN = 12


class AESCipher:
    def __init__(self, key: str):
        raw = key.encode()
        if len(raw) < 32:
            raise ValueError(
                "ENCRYPTION_KEY must be at least 32 bytes. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(16))\""
            )
        self.key = raw[:32]  # AES-256 uses exactly 32 bytes
        self.backend = default_backend()
        self._gcm = AESGCM(self.key)

    def encrypt(self, raw: str) -> str:
        nonce = os.urandom(_NONCE_LEN)
        ct = self._gcm.encrypt(nonce, raw.encode(), None)
        return base64.b64encode(_MAGIC + nonce + ct).decode()

    def decrypt(self, enc: str) -> str:
        raw_bytes = base64.b64decode(enc)

        if raw_bytes[:4] == _MAGIC:
            nonce = raw_bytes[4:4 + _NONCE_LEN]
            ct = raw_bytes[4 + _NONCE_LEN:]
            return self._gcm.decrypt(nonce, ct, None).decode()

        # Legacy v1 (AES-CFB, no MAGIC prefix) — decrypt-only compatibility path.
        iv = raw_bytes[:16]
        ct = raw_bytes[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode()


aes_cipher = AESCipher(settings.ENCRYPTION_KEY)
