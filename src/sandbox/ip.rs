// IP检测：通过ip-api.com获取IP归属地，若非中国则判定为沙箱或代理环境
#[cfg(feature = "vm_check_ip")]
pub fn check_ip() -> bool {
    use obfstr::obfstr;
    match crate::utils::http_get(obfstr!("http://ip-api.com/csv")) {
        Ok((status_code, body)) => {
            if status_code == 200 {
                let body_str = String::from_utf8_lossy(&body);
                if body_str.contains(obfstr!("China")) {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        Err(_) => false,
    }
}
