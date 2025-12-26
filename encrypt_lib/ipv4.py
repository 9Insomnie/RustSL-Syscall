name = 'ipv4'
description = 'Encode binary as IPv4 addresses (comma separated) with leading sha256 and length'

import hashlib
import base64
import binascii

def sha256_bytes(b):
	sha = hashlib.sha256()
	sha.update(b)
	return sha.digest()

def bytes_to_ipv4(b):
	return '.'.join(str(x) for x in b)

def process(data, args):
    addresses = []
    for i in range(0, len(data), 4):
        addr_bytes = data[i:i+4]
        if len(addr_bytes) < 4:
            addr_bytes += b'\x00' * (4 - len(addr_bytes))
        addresses.append(bytes_to_ipv4(addr_bytes))
    hash1 = sha256_bytes(data)
    hash_str = binascii.hexlify(hash1).decode()
    len_str = str(len(data))
    ipv4_str = ','.join(addresses)
    final = f"{hash_str},{len_str},{ipv4_str}"
    return final.encode('utf-8')