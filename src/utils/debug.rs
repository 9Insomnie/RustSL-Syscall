#[cfg(feature = "debug")]
use colored::*;
#[cfg(feature = "debug")]
use lazy_static::lazy_static;

#[cfg(feature = "debug")]
lazy_static! {
    static ref START_TIME: std::time::Instant = std::time::Instant::now();
}

#[cfg(feature = "debug")]
#[track_caller]
fn print_log(
    symbol: &str,
    symbol_color: &str,
    loc_color: &str,
    prefix: &str,
    msg: &str,
    msg_color: &str,
) {
    let loc = std::panic::Location::caller();
    let file = std::path::Path::new(loc.file())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(loc.file());

    let elapsed = START_TIME.elapsed().as_secs_f32();
    let time_tag = format!("[{:>04.2}s]", elapsed).bright_black();

    // 第一行：时间戳 + Emoji + 源码位置
    println!(
        "{} {}  {}",
        time_tag,
        symbol.color(symbol_color).bold(),
        format!("{}:{}", file, loc.line()).color(loc_color).dimmed()
    );

    let connector = "         ┗━❯".bright_black();
    if prefix.is_empty() {
        println!("{} {}", connector, msg.color(msg_color).bold());
    } else {
        println!(
            "{} {}: {}",
            connector,
            prefix.color(msg_color).bold(),
            msg.color(msg_color)
        );
    }
}

#[cfg(feature = "debug")]
#[track_caller]
pub fn print_error(prefix: &str, error: &dyn std::fmt::Display) {
    print_log(
        "🟥",
        "bright_red",
        "blue",
        prefix,
        &format!("{}", error),
        "red",
    );
}

#[cfg(feature = "debug")]
#[track_caller]
pub fn print_message(msg: &str) {
    print_log("🟦", "bright_blue", "cyan", "", msg, "blue");
}

#[cfg(feature = "debug")]
#[track_caller]
pub fn print_success(msg: &str) {
    print_log("🟩", "green", "cyan", "", msg, "green");
}
