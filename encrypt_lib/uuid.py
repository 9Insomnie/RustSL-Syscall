name = 'uuid'
description = 'Interpret binary as sequence of UUIDs (16-byte blocks) with leading sha256 and length'

import uuid
import hashlib
import binascii

def sha256_bytes(b):
	sha = hashlib.sha256()
	sha.update(b)
	return sha.digest()


def process(data, args):
    original_len = len(data)
    # pad to 16-byte multiple
    pad_len = (16 - (len(data) % 16)) % 16
    if pad_len:
        data = data + (b'\x00' * pad_len)
    uuids = []
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        u = uuid.UUID(bytes=block)
        uuids.append(str(u))
    hash1 = sha256_bytes(data)
    hash_str = binascii.hexlify(hash1).decode()
    len_str = str(original_len)
    uuid_str = ','.join(uuids)
    final = f"{hash_str},{len_str},{uuid_str}"
    return final.encode()
