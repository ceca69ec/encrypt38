// encrypt38/src/main.rs
// 20210706
// ceca69ec8e1bcad6c6d79e1dcf7214ff67766580a62b7d19a6fb094c97b4f2dc

//! Encrypt a private key with bip-0038 standard and do the reverse.
//! Generate elliptic curve encrypted key if just the passphrase is informed.

use encrypt38::{handle_arguments, init_clap};

/// Whirlpool of the project.
fn main() {
    handle_arguments(init_clap().get_matches()).unwrap_or_else(|err| {
        clap::Error::with_description(
            err.message(),
            clap::ErrorKind::InvalidValue
        ).exit();
    });
}
