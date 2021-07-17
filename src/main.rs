//! Encrypt a private key with bip-0038 standard and do the reverse.
//! Generate elliptic curve encrypted key if just the passphrase is informed.

use encrypt38::{handle_arguments, init_clap};

/// Whirlpool of the project.
fn main() {
    handle_arguments(init_clap().get_matches()).unwrap_or_else(|err| {
        eprintln!("\x1b[31m\x1b[1merror\x1b[m: {}", err);
        std::process::exit(err.status());
    });
}
