#[cfg(feature = "debug")]
use colored::*;

#[cfg(feature = "debug")]
#[track_caller]
pub fn print_error(prefix: &str, error: &dyn std::fmt::Display) {
    let loc = std::panic::Location::caller();

    let file = std::path::Path::new(loc.file())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(loc.file());

    println!(
        "{} {}",
        "[!]".bright_red().bold(),
        format!("[{}:{}]", file, loc.line()).blue()
    );

    println!(
        "  {} {}: {}",
        "↳".bright_magenta(),
        prefix.red().bold(),
        format!("{}", error).red()
    );
}

#[cfg(feature = "debug")]
#[track_caller]
pub fn print_message(msg: &str) {
    let loc = std::panic::Location::caller();
    let file = std::path::Path::new(loc.file())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(loc.file());

    println!(
        "{} {}",
        "[+]".green().bold(),
        format!("[{}:{}]", file, loc.line()).cyan()
    );

    println!(
        "  {} {}",
        "↳".bright_magenta(),
        msg.green().bold()
    );
}