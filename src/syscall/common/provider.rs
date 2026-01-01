use super::r#type::SyscallData;

pub enum ResolvedSyscall {
    Indirect(SyscallData),
    Direct(usize),
}

pub trait SyscallProvider {
    fn resolve(base: *mut u8, hash: u32) -> Option<ResolvedSyscall>;
}
