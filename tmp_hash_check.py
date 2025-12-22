def dbj2_hash(buf):
    h = 0x811c9dc5
    for i, b in enumerate(buf):
        cur = b
        if cur == 0:
            continue
        if 97 <= cur <= 122:
            cur &= ~0x20
        h = ((h << 5) + h) & 0xFFFFFFFF
        mix = (cur + i) & 0xFFFFFFFF
        rot = i % 16
        if rot == 0:
            rot_val = mix
        else:
            rot_val = ((mix << rot) & 0xFFFFFFFF) | (mix >> (32 - rot))
        h ^= rot_val
    v = h
    v ^= (v >> 16)
    v = (v * 0x85ebca6b) & 0xFFFFFFFF
    v ^= (v >> 13)
    v = (v * 0xc2b2ae35) & 0xFFFFFFFF
    v ^= (v >> 16)
    return v

candidates = [b"ntdll.dll\0", b"ntdll.dll", b"NTDLL.DLL\0", b"kernel32.dll\0", b"kernel32.dll"]
for c in candidates:
    print(c, hex(dbj2_hash(c)))

print('\nlogged hash to search: 0x6222e307')
