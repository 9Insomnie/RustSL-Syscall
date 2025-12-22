use windows_sys::Win32::System::Memory::*;

/// Generates the assembly stub for indirect syscall:
/// mov r10, rcx
/// mov eax, <ssn>
/// mov r11, <gadget>
/// jmp r11
pub fn get_stub(ssn: u16, gadget: *mut u8) -> Vec<u8> {
    let mut stub = Vec::with_capacity(21);

    // mov r10, rcx
    stub.extend_from_slice(&[0x4C, 0x8B, 0xD1]);

    // mov eax, ssn
    stub.push(0xB8);
    stub.extend_from_slice(&(ssn as u32).to_le_bytes());

    // mov r11, gadget
    stub.extend_from_slice(&[0x49, 0xBB]);
    stub.extend_from_slice(&(gadget as u64).to_le_bytes());

    // jmp r11
    stub.extend_from_slice(&[0x41, 0xFF, 0xE3]);

    stub
}

/// Allocates RWX memory and writes the assembly stub
pub unsafe fn create_indirect_stub(ssn: u16, gadget: *mut u8) -> Option<*mut u8> {
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("KFD: Creating indirect stub for SSN: {:#x} jumping to {:p}", ssn, gadget));

    let stub_code = get_stub(ssn, gadget);

    // Allocate executable memory for the stub
    // Note: We use VirtualAlloc directly to avoid recursion if syscall! is configured to use KFD
    let stub_ptr = VirtualAlloc(
        std::ptr::null(),
        stub_code.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if stub_ptr.is_null() {
        #[cfg(feature = "debug")]
        crate::utils::print_error("KFD", &"VirtualAlloc failed for stub generation");
        return None;
    }

    std::ptr::copy_nonoverlapping(stub_code.as_ptr(), stub_ptr as *mut u8, stub_code.len());
    
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("KFD: Indirect stub created at {:p}", stub_ptr));

    Some(stub_ptr as *mut u8)
}
