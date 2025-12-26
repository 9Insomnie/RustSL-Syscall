use crate::alloc::alloc;
use obfstr::obfstr;
pub unsafe fn decrypt(decoded: &[u8]) -> Result<(usize, usize), String> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    use obfstr::obfstr;
    
    let key_len = 32;  // AES-256 key size
    let iv_len = 16;   // GCM nonce size
    let tag_len = 16;  // GCM tag size
    
    if decoded.len() < key_len + iv_len + tag_len {
        return Err(obfstr!("aes payload too short").to_string());
    }
    
    let key = &decoded[0..key_len];
    let iv = &decoded[key_len..key_len + iv_len];
    let tag = &decoded[key_len + iv_len..key_len + iv_len + tag_len];
    let encrypted = &decoded[key_len + iv_len + tag_len..];
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    
    let mut ciphertext_with_tag = encrypted.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);
    
    let plaintext = cipher.decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|_| obfstr!("aes decryption failed").to_string())?;
    
    let pt_len = plaintext.len();
    let p = unsafe { alloc(pt_len)? };
    std::ptr::copy_nonoverlapping(plaintext.as_ptr(), p, pt_len);
    
    Ok((p as usize, pt_len))
}