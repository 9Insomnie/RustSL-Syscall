#![allow(dead_code, unused_imports)]

mod http;
pub use http::http_get;

pub mod hash;
pub use hash::dbj2_hash;

mod load_api;
pub use load_api::{
    load_library,
    get_proc_address
};

#[cfg(feature = "debug")]
mod debug;
#[cfg(feature = "debug")]
pub use debug::{
    print_message,
    print_error
};

pub fn simple_decrypt(encrypted: &str) -> String {
    use obfstr::obfbytes;
    use base64::{Engine as _, engine::general_purpose};
    let decoded = general_purpose::STANDARD.decode(encrypted).unwrap();
    let obf_key = obfbytes!(b"rsl_secret_key_2025");
    let key = obf_key.as_slice();
    let decrypted: Vec<u8> = decoded.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect();
    String::from_utf8(decrypted).unwrap()
}

pub fn sys_encode_fn_pointer(ptr: usize) -> usize {
    let kuser_shared_data = 0x7FFE0000 as *const u8;
    let cookie_ptr = unsafe { kuser_shared_data.add(0x330) as *const u32 };
    let cookie = unsafe { *cookie_ptr } as usize;
    
    let mut encoded = ptr ^ cookie;
    let rotate = (cookie & 0x3F) as u32;
    
    encoded = encoded.rotate_right(rotate);
    
    encoded
}

pub mod veh_hwbp;
pub mod handle;
pub use handle::Handle;

pub mod error;
pub use error::{RslError, RslResult};
