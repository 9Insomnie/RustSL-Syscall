
#[allow(dead_code)]
pub fn decode(data: &[u8]) -> Option<Vec<u8>> {
    let _ = data;
    #[cfg(feature = "base32_decode")]
    return {
        let raw = std::str::from_utf8(data).ok()?;
        base32::decode(base32::Alphabet::Rfc4648 { padding: true }, raw)
    };

    #[cfg(feature = "base64_decode")]
    return {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(data).ok()
    };

    #[cfg(feature = "urlsafe_base64_decode")]
    return {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE.decode(data).ok()
    };

    #[cfg(feature = "hex_decode")]
    return {
        let raw = std::str::from_utf8(data).ok()?;
        hex::decode(raw.trim()).ok()
    };

    #[cfg(any(feature = "none_decode", not(any(
        feature = "base32_decode",
        feature = "base64_decode",
        feature = "urlsafe_base64_decode",
        feature = "hex_decode"
    ))))]
    return {
        Some(data.to_vec())
    };
}