#[cfg(feature = "vm_check_edge")]
mod edge;
#[cfg(feature = "vm_check_ip")]
mod ip;
#[cfg(feature = "vm_check_prime")]
mod prime;
#[cfg(feature = "vm_check_rdtsc_timing")]
mod rdtsc_timing;

#[cfg(feature = "debug")]
use crate::utils::print_message;

use rsl_macros::obfuscation_noise_macro;

#[cfg(feature = "sandbox")]
pub fn guard_vm() -> bool {
    #[cfg(feature = "vm_check_rdtsc_timing")]
    {
        let sleep_ms: u64 = 500;
        let threshold_ratio: f64 = 0.8;
        if rdtsc_timing::check_rdtsc_sandboxed(sleep_ms, threshold_ratio) { return true; }
        else {
            #[cfg(feature = "debug")]
            print_message("RDTSC timing check passed.");
            obfuscation_noise_macro!();
        }
    }

    #[cfg(feature = "vm_check_prime")]
    if !prime::check_prime() { return true; }
    else {
        #[cfg(feature = "debug")]
        print_message("Prime number check passed.");
        obfuscation_noise_macro!();
    }

    #[cfg(feature = "vm_check_ip")]
    if !ip::check_ip() { return true; }
    else {
        #[cfg(feature = "debug")]
        print_message("IP address check passed.");
        obfuscation_noise_macro!();
    }

    #[cfg(feature = "vm_check_edge")]
    if !edge::check_edge() { return true; }
    else {
        #[cfg(feature = "debug")]
        print_message("Microsoft Edge check passed.");
        obfuscation_noise_macro!();
    }
    false
}
