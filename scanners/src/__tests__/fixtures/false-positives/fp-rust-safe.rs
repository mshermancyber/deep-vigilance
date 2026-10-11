// fp-rust-safe.rs: Safe Rust with no unsafe or command injection — SAFE
use std::fs;

fn read_config() -> String {
    // SAFE: reading a hardcoded file path, no user input
    match fs::read_to_string("/etc/app/config.toml") {
        Ok(content) => content,
        Err(_) => String::from("default"),
    }
}

fn main() {
    let config = read_config();
    println!("{}", config);
}
