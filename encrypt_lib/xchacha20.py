name = 'xchacha20'
description = 'XChaCha20-Poly1305 AEAD with 24-byte nonce; payload: [Key(32)][Nonce(24)][Tag(16)][Ciphertext]'

import os
import hashlib

def process(data, args):
    try:
        from Crypto.Cipher import ChaCha20_Poly1305
    except Exception:
        raise RuntimeError("pycryptodome is required for xchacha20 plugin")

    key = os.urandom(32)
    nonce = os.urandom(24)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    final = key + nonce + tag + ciphertext
    return final