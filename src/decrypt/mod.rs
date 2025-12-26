#[cfg(feature = "decrypt_ipv4")]
mod ipv4;
#[cfg(feature = "decrypt_ipv6")]
mod ipv6;
#[cfg(feature = "decrypt_uuid")]
mod uuid;
#[cfg(feature = "decrypt_mac")]
mod mac;
#[cfg(feature = "decrypt_rc4")]
mod rc4;
#[cfg(feature = "decrypt_aes")]
mod aes;
#[cfg(feature = "decrypt_xchacha20")]
mod xchacha20;
#[cfg(feature = "decrypt_ecc")]
mod ecc;

#[allow(unreachable_code)]
pub unsafe fn decrypt( decoded: &[u8]) -> Result<(usize, usize), String> {
	#[cfg(feature = "decrypt_ipv4")]
	{
		return ipv4::decrypt(decoded);
	}
	#[cfg(feature = "decrypt_ipv6")]
	{
		return ipv6::decrypt(decoded);
	}
	#[cfg(feature = "decrypt_uuid")]
	{
		return uuid::decrypt(decoded);
	}
	#[cfg(feature = "decrypt_mac")]
	{
		return mac::decrypt(decoded);
	}
	#[cfg(feature = "decrypt_rc4")]
	{
		return rc4::decrypt(decoded);
	}
	#[cfg(feature = "decrypt_aes")]
	{
		return aes::decrypt(decoded);
	}
	#[cfg(feature = "decrypt_xchacha20")]
	{
		return xchacha20::decrypt(decoded);
	}
	#[cfg(feature = "decrypt_ecc")]
	{
		return ecc::decrypt(decoded);
	}
	Err("No decryption method enabled".to_string())
}