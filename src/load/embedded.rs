pub fn load() -> crate::utils::error::RslResult<Vec<u8>> {
    const ENCRYPT_DATA: &'static [u8] = include_bytes!("../../output/encrypt.bin");
    Ok(ENCRYPT_DATA.to_vec())
}
