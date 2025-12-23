use std::arch::asm;
use crate::syscall::common::SyscallData;

pub trait ToSyscallArg { fn to_arg(self) -> usize; }
impl ToSyscallArg for usize { fn to_arg(self) -> usize { self } }
impl ToSyscallArg for isize { fn to_arg(self) -> usize { self as usize } }
impl ToSyscallArg for u64 { fn to_arg(self) -> usize { self as usize } }
impl ToSyscallArg for i64 { fn to_arg(self) -> usize { self as usize } }
impl ToSyscallArg for u32 { fn to_arg(self) -> usize { self as usize } }
impl ToSyscallArg for i32 { fn to_arg(self) -> usize { self as usize } }
impl ToSyscallArg for u16 { fn to_arg(self) -> usize { self as usize } }
impl ToSyscallArg for u8  { fn to_arg(self) -> usize { self as usize } }
impl<T> ToSyscallArg for *const T { fn to_arg(self) -> usize { self as usize } }
impl<T> ToSyscallArg for *mut T   { fn to_arg(self) -> usize { self as usize } }
impl<T> ToSyscallArg for &T       { fn to_arg(self) -> usize { self as *const T as usize } }
impl<T> ToSyscallArg for &mut T   { fn to_arg(self) -> usize { self as *mut T as usize } }

/// Minimal direct indirect-syscall bridge.
/// Loads SSN into EAX, marshals args into syscall registers/stack, then CALLs the syscall instruction.
#[no_mangle]
pub unsafe extern "C" fn direct_syscall_bridge(
    ssn: u16,
    syscall_inst: usize,
    args: *const usize,
    num_args: usize,
) -> usize {
    let mut result: usize;
    asm!(
        "cld", // Clear direction flag for safety
        // Preserve non-volatile registers we touch
        "push rbp", "push rbx", "push r12", "push r13", "push r14", "push r15",
        "mov rbp, rsp",

        // rdx = syscall_inst, rcx = ssn, r8 = args, r9 = num_args
        "mov ebx, ecx",      // ssn -> ebx
        "mov r11, rdx",      // syscall_inst -> r11 (callee)

        // stack space for shadow + extra args (beyond 4)
        // Logic: size = max(0, num_args - 4) * 8 + 32 (shadow)
        // Then align to 16 bytes and add 8 to ensure rsp % 16 == 0 after 'sub rsp, size'
        // (because current rsp % 16 == 8 due to return address + 6 pushes)
        "xor r10, r10",      // r10 = 0
        "mov r12, r9",       // n = num_args
        "sub r12, 4",
        "cmovl r12, r10",    // if negative set to 0
        "shl r12, 3",        // *8
        "add r12, 32",       // shadow space
        "add r12, 15",
        "and r12, -16",      // align
        "add r12, 8",        // keep 16-byte alignment after call
        "sub rsp, r12",

        // copy stack args (5+)
        "cmp r9, 4",
        "jbe 4f",
        "mov r13, r9",
        "sub r13, 4",
        "lea r14, [r8 + 32]", // args[4]
        "xor r15, r15",
        "5:",
        "mov rax, [r14 + r15*8]",
        "mov [rsp + 32 + r15*8], rax",
        "inc r15",
        "cmp r15, r13",
        "jl 5b",

        "4:",
        // load first four args
        "xor r12, r12", "xor r13, r13", "xor r14, r14", "xor r15, r15",
        "test r9, r9", "jz 3f",
        "mov r12, [r8]",        // a1
        "cmp r9, 1", "jbe 3f",
        "mov r13, [r8 + 8]",    // a2
        "cmp r9, 2", "jbe 3f",
        "mov r14, [r8 + 16]",   // a3
        "cmp r9, 3", "jbe 3f",
        "mov r15, [r8 + 24]",   // a4

        "3:",
        // syscall register mapping
        "mov r10, r12", // RCX -> R10
        "mov rdx, r13", // RDX
        "mov r8,  r14", // R8
        "mov r9,  r15", // R9
        "mov eax, ebx", // SSN

        "call r11",      // jump to the syscall instruction

        // restore
        "mov rsp, rbp",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
        out("rax") result,
        in("rcx") ssn,
        in("rdx") syscall_inst,
        in("r8") args,
        in("r9") num_args,
        clobber_abi("C"),
    );
    result
}

pub unsafe fn direct_invoke_generic(data: &SyscallData, args: &[usize]) -> usize {
    if data.syscall_inst == 0 {
        // STATUS_UNSUCCESSFUL or similar error code to indicate failure
        return 0xC0000001;
    }
    direct_syscall_bridge(data.ssn, data.syscall_inst, args.as_ptr(), args.len())
}
