name = 'aes'
description = 'AES-GCM encrypt with random 32-byte key and 16-byte IV, output [key(32)][iv(16)][tag(16)][encrypted]'

import os
import hashlib

def sha256_bytes(b):
    sha = hashlib.sha256()
    sha.update(b)
    return sha.digest()

def process(data, args):
    try:
        from Crypto.Cipher import AES
    except Exception:
        raise RuntimeError('pycryptodome is required for aes plugin')
    
    # generate key and iv
    key = os.urandom(32)
    iv = os.urandom(16)
    
    cipher = AES.new(key, AES.MODE_GCM, iv)
    encrypted, tag = cipher.encrypt_and_digest(data)
    final = key + iv + tag + encrypted
    return final