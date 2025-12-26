name = 'aes'
description = 'AES-GCM encrypt with random 32-byte key and 12-byte nonce, output [key(32)][nonce(12)][tag(16)][encrypted]'

import os

def process(data, args):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception:
        raise RuntimeError('cryptography is required for aes plugin')
    
    # generate key and nonce
    key = os.urandom(32)
    nonce = os.urandom(12)
    
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)
    # encrypted includes ciphertext + tag (16 bytes)
    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]
    final = key + nonce + tag + ciphertext
    return final