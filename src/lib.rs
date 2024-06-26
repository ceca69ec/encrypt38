//! **Command line tool to encrypt and decrypt bitcoin private keys with
//! [bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard.**
//!
//! ## Basic usage
//!
//! ```console
//! $ encrypt38 -p Satoshi KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7
//! 6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7
//! ```
//!
//! ```console
//! $ encrypt38 -p Satoshi 6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7
//! 09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae
//! KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7
//! ```
//!
//! ## Disclaimer
//!
//! * **Don't trust, verify**
//!
//!     Compare the results of this tool with others. Verify the implementation (and the tests).
//! Decrypt immediately after an encryption to check the passphrase you *typed* was the one you
//! *wanted*. **Use at your won risk.**
//!
//! * **Not recommended**
//!
//!     Use this tool only to decrypt keys you already have. The method of keeping private keys
//! encrypted with bip-0038 standard is [not recommended](https://youtu.be/MbwLVok4gWA?t=2462)
//! anymore (use [mnemonic](https://crates.io/crates/mnemonic39) instead).
//!
//! ## Features
//!
//! * **Address**
//!
//!     This tool show the respective address of a decrypted private key in the legacy,
//! segwit-nested and segwit-native formats according to the version prefix of the encrypted
//! private key.
//!
//! * **Custom separator**
//!
//!     Customization of the default separator of information when decrypting.
//!
//! * **Decryption**
//!
//!     Insert an encrypted private key `6P...` and passphrase do show the private key represented
//! in hexadecimal and the respective address, public key and wif keys.
//!
//! * **Encryption**
//!
//!     Insert a private key in the form of hexadecimal numbers or wif key and passphrase to show
//! the encrypted private key.
//!
//! * **Generation (elliptic curve multiplication method)**
//!
//!     Insert a passphrase to create an encrypted private key using pseudo-random number generation
//! and elliptic curve multiplication.
//!
//! * **Uncompressed address**
//!
//!     This tool is capable of resulting in uncompressed address (mainly for decryption and retro
//! compatibility, *not recommended*).
//!
//! ## Help
//!
//! ```shell
//! Insert encrypted, hexadecimal or wif private key and passphrase to decrypt or
//! encrypt accordingly. Insert only passphrase to create an encrypted private key
//! using elliptic curve multiplication (and pseudo-random number generation).
//!
//! Usage: encrypt38 [OPTIONS] -p <passphrase> [PRIVATE_KEY]
//!
//! Arguments:
//!   [PRIVATE_KEY]  Hexadecimal, wif or encrypted private key
//!
//! Options:
//!   -s <separator>       Specify character (or string) to separate verbose result
//!   -p <passphrase>      Used to encrypt and decrypt the private key (required)
//!   -u, --uncompressed   Encrypted private key to generate uncompressed address
//!   -v, --verbose        Show possible address and public key when decrypting
//!   -h, --help           Print help
//!   -V, --version        Print version
//! ```
//!
//! ## Installation
//!
//! You have to install [rust](https://www.rust-lang.org/tools/install) and a
//!  [linker](https://gcc.gnu.org/wiki/InstallingGCC) if you don't already have them.
//!
//! ```shell
//! $ cargo install encrypt38
//! ```

use bip38::{Decrypt, Encrypt, Generate};
use bitcoin_bech32::constants::Network;
use bitcoin_bech32::{u5, WitnessProgram};
use clap::{
    builder::OsStringValueParser, builder::TypedValueParser, crate_version, Arg, ArgAction,
    ArgMatches, Command,
};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Digest;
use std::ffi::OsString;

/// Information to user.
const ABOUT: &str = "Insert encrypted, hexadecimal or wif private key and passphrase to decrypt or
encrypt accordingly. Insert only passphrase to create an encrypted private key
using elliptic curve multiplication (and pseudo-random number generation).";

/// Number of characters of an encrypted private key.
const LEN_EKEY: usize = 58;

/// Number of characters in wif compressed secret key.
const LEN_WIF_C: usize = 52;

/// Number of characters in wif uncompressed secret key.
const LEN_WIF_U: usize = 51;

/// Number of bytes of a public key compressed.
const NBBY_PUBC: usize = 33;

/// Number of bytes of a public key uncompressed.
const NBBY_PUBU: usize = 65;

/// Number of bytes (payload only) contained in a decoded wif compressed key.
const NBBY_WIFC: usize = 34;

/// Number of bytes (payload only) contained in a decoded wif uncompressed key.
const NBBY_WIFU: usize = 33;

/// Byte of 'OP_0' in the Script language.
const OP_0: u8 = 0x00;

/// Byte to push the next 20 bytes in the Script language.
const OP_PUSH20: u8 = 0x14;

/// Prefix of all private keys encrypted with bip-0038 standard.
const PRE_EKEY: &str = "6P";

/// Prefix of all ec encrypted keys.
const PRE_EC: [u8; 2] = [0x01, 0x43];

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// Prefix of all p2wpkh-p2sh address in main net.
const PRE_P2WPKH_P2SH_B: u8 = 0x05;

/// First two possible characters of wif compressed.
const PRE_WIF_C: &str = "KL";

/// First byte of all wif encoded secret keys.
const PRE_WIF_B: u8 = 0x80;

/// First character of wif uncompressed.
const PRE_WIF_U: &str = "5";

/// Default string used to separate resulting information.
const SEP_DEFAULT: &str = " | ";

/// Prefix of all warning output messages;
const WARN: &str = "\x1b[33m\x1b[1mwarning\x1b[m: ";

/// Errors of 'encrypt38' project.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
#[doc(hidden)]
pub enum Error {
    /// If an invalid base 58 string is processed.
    Base58,
    /// Bech32 error.
    Bech32,
    /// Error provenient of the bip38 dependency
    Bip38(bip38::Error),
    /// Invalid checksum was found.
    Check,
    /// Found invalid encrypted private key.
    EncKey,
    /// Flag 'u' invalid in the context (encrypted or wif private keys).
    FlagU,
    /// Found invalid hexadecimal representation of an secret key.
    HexKey,
    /// Found invalid hexadecimal value represented in string.
    HexStr,
    /// Showed if an invalid argument is found.
    InvArg,
    /// Invalid number of public key bytes.
    NbPubB,
    /// Error while parsing the arguments.
    Parser,
    /// Input is not valid encrypted, hexadecimal or wif private key.
    Prvk,
    /// Invalid secret entropy was found (could not generate address).
    SecEnt,
    /// Invalid wif secret key.
    WifKey,
}

/// Functions to manipulate data in form of arbitrary number of bytes [u8].
trait BytesManipulation {
    /// Encode target arbitrary number of bytes in base 58 check.
    fn encode_base58ck(&self) -> String;

    /// Sha256 and ripemd160 in sequence.
    fn hash160(&self) -> [u8; 20];

    /// Receives a arbitrary number of bytes and return 32 bytes of a dual sha256 hash of them.
    fn hash256(&self) -> [u8; 32];

    /// Receives bytes and return a string of hexadecimal characters.
    fn hex_string(&self) -> String;

    /// Create an p2wpkh address according to inserted self key bytes.
    fn p2wpkh(&self) -> Result<String, Error>;
}

/// Functions to manipulate private keys (32 bytes).
trait PrivateKeyManipulation {
    /// Generate secp256k1 point based on target secret key.
    fn public(&self, compress: bool) -> Result<Vec<u8>, Error>;

    /// Generate a representation of secret key in wif format.
    fn wif(&self, compress: bool) -> String;
}

/// Functions to manipulate compressed public keys (33 bytes).
trait PublicKeyCompressedManipulation {
    /// Generate an segwit address of a compressed public key.
    fn segwit_p2wpkh(&self) -> Result<String, Error>;

    /// Generate an segwit address according to informed compressed public key.
    fn segwit_p2wpkh_p2sh(&self) -> Result<String, Error>;
}

/// Functions to manipulate strings.
trait StringManipulation {
    /// Decode informed base 58 string into bytes (payload only).
    fn decode_base58ck(&self) -> Result<Vec<u8>, Error>;

    /// Decode a secret key encoded in base 58 returning bytes and compression.
    fn decode_wif(&self) -> Result<([u8; 32], bool), Error>;

    /// Transform string of hexadecimal characters into a vector of bytes.
    fn hex_bytes(&self) -> Result<Vec<u8>, Error>;

    /// Test if an string of arbitrary length contains only hexadecimal chars.
    fn is_hex(&self) -> bool;

    /// Show decryption of target string in command line interface.
    fn show_decrypt(&self, pass: &str, separator: &str, verbose: bool) -> Result<(), Error>;

    /// Show encryption of target string in command line interface.
    fn show_encrypt(&self, pass: &str, compress: bool) -> Result<(), Error>;
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Base58 => write!(f, "invalid base58 string"),
            Error::Bech32 => write!(f, "invalid bech32 data"),
            Error::Bip38(err) => write!(f, "{}", err),
            Error::Check => write!(f, "invalid checksum"),
            Error::EncKey => write!(f, "invalid encrypted private key"),
            Error::FlagU => write!(
                f,
                "flag '\x1b[33muncompressed\x1b[m' invalid in this context (aborted)"
            ),
            Error::HexKey => write!(f, "invalid hexadecimal private key"),
            Error::HexStr => write!(f, "invalid hexadecimal string"),
            Error::InvArg => write!(f, "invalid argument"),
            Error::NbPubB => write!(f, "invalid number of public bytes"),
            Error::Parser => write!(f, "fatal problem while parsing arguments"),
            Error::Prvk => write!(f, "not an encrypted, hexadecimal or wif private key"),
            Error::SecEnt => write!(f, "invalid secret entropy"),
            Error::WifKey => write!(f, "invalid wif secret key"),
        }
    }
}

impl From<bip38::Error> for Error {
    fn from(err: bip38::Error) -> Self {
        Error::Bip38(err)
    }
}

/// Implementation of trait BytesManipulation.
impl BytesManipulation for [u8] {
    #[inline]
    fn encode_base58ck(&self) -> String {
        let mut decoded: Vec<u8> = self.to_vec();
        decoded.append(&mut decoded.hash256()[..4].to_vec());
        bs58::encode(decoded).into_string()
    }

    #[inline]
    fn hash160(&self) -> [u8; 20] {
        let mut result = [0x00; 20];
        result[..].copy_from_slice(&Ripemd160::digest(&sha2::Sha256::digest(self)));
        result
    }

    #[inline]
    fn hash256(&self) -> [u8; 32] {
        let mut result = [0x00; 32];
        result[..].copy_from_slice(&sha2::Sha256::digest(&sha2::Sha256::digest(self)));
        result
    }

    #[inline]
    fn hex_string(&self) -> String {
        let mut result = String::new();
        for byte in self {
            result = format!("{}{:02x}", result, byte);
        }
        result
    }

    #[inline]
    fn p2wpkh(&self) -> Result<String, Error> {
        if self.len() != NBBY_PUBC && self.len() != NBBY_PUBU {
            return Err(Error::NbPubB);
        }
        let mut address_bytes = vec![0x00];
        address_bytes.append(&mut self.hash160().to_vec());
        Ok(address_bytes.encode_base58ck())
    }
}

/// Implementation of enum Error.
impl Error {
    /// Retrieve the status code to be showed when exiting because of an error.
    #[doc(hidden)]
    pub fn status(&self) -> i32 {
        match self {
            Error::Base58 => 1,
            Error::Bech32 => 2,
            Error::Bip38(_) => 3,
            Error::Check => 4,
            Error::EncKey => 5,
            Error::FlagU => 6,
            Error::HexKey => 7,
            Error::HexStr => 8,
            Error::InvArg => 9,
            Error::NbPubB => 10,
            Error::Parser => 11,
            Error::Prvk => 12,
            Error::SecEnt => 13,
            Error::WifKey => 14,
        }
    }
}

/// Implementation of trait PrivateKeyManipulation.
impl PrivateKeyManipulation for [u8; 32] {
    #[inline]
    fn public(&self, compress: bool) -> Result<Vec<u8>, Error> {
        let secp_pub = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(self).map_err(|_| Error::SecEnt)?,
        );
        if compress {
            Ok(secp_pub.serialize().to_vec())
        } else {
            Ok(secp_pub.serialize_uncompressed().to_vec())
        }
    }

    #[inline]
    fn wif(&self, compress: bool) -> String {
        let mut decoded: Vec<u8> = vec![PRE_WIF_B];
        decoded.append(&mut self.to_vec());
        if compress {
            decoded.push(0x01);
        }
        decoded.encode_base58ck()
    }
}

/// Implementation of trait PublicKeyCompressedManipulation.
impl PublicKeyCompressedManipulation for [u8; NBBY_PUBC] {
    #[inline]
    fn segwit_p2wpkh(&self) -> Result<String, Error> {
        // segwit version has to be inserted as 5 bit unsigned integer
        let witness_program = WitnessProgram::new(
            u5::try_from_u8(0).map_err(|_| Error::Bech32)?,
            self.hash160().to_vec(),
            Network::Bitcoin,
        )
        .map_err(|_| Error::Bech32)?;
        Ok(witness_program.to_address())
    }

    #[inline]
    fn segwit_p2wpkh_p2sh(&self) -> Result<String, Error> {
        let mut redeem_script = vec![OP_0, OP_PUSH20];
        redeem_script.append(&mut self.hash160().to_vec());
        let mut address_bytes = vec![PRE_P2WPKH_P2SH_B];
        address_bytes.append(&mut redeem_script.hash160().to_vec());
        Ok(address_bytes.encode_base58ck())
    }
}

/// Implementation of trait StringManipulation.
impl StringManipulation for str {
    #[inline]
    fn decode_base58ck(&self) -> Result<Vec<u8>, Error> {
        let raw = bs58::decode(self).into_vec().map_err(|_| Error::Base58)?;
        if raw[raw.len() - 4..] == raw[..raw.len() - 4].hash256()[..4] {
            Ok(raw[..(raw.len() - 4)].to_vec())
        } else {
            Err(Error::Check)
        }
    }

    #[inline]
    fn decode_wif(&self) -> Result<([u8; 32], bool), Error> {
        if (!self.is_char_boundary(1) || !PRE_WIF_C.contains(&self[..1]) || self.len() != LEN_WIF_C)
            && (!self.starts_with(PRE_WIF_U) || self.len() != LEN_WIF_U)
        {
            return Err(Error::WifKey);
        }
        let raw_bytes = self.decode_base58ck()?;
        if (raw_bytes.len() != NBBY_WIFC && raw_bytes.len() != NBBY_WIFU)
            || raw_bytes[0] != PRE_WIF_B
        {
            return Err(Error::WifKey);
        }
        let mut result = [0x00; 32];
        result[..].copy_from_slice(&raw_bytes[1..33]);
        Ok((result, raw_bytes.len() == NBBY_WIFC))
    }

    #[inline]
    fn hex_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for index in (0..self.len()).step_by(2) {
            out.push(u8::from_str_radix(&self[index..index + 2], 16).map_err(|_| Error::HexStr)?);
        }
        Ok(out)
    }

    #[inline]
    fn is_hex(&self) -> bool {
        for c in self.chars() {
            if !c.is_ascii_hexdigit() {
                return false;
            }
        }
        true
    }

    #[inline]
    fn show_decrypt(&self, pass: &str, separator: &str, verbose: bool) -> Result<(), Error> {
        let decoded = self.decode_base58ck()?;
        let (prvk, compress) = if decoded[..2] == PRE_NON_EC || decoded[..2] == PRE_EC {
            self.decrypt(pass)?
        } else {
            return Err(Error::EncKey);
        };

        let prvk_hex = prvk.hex_string();
        let wif = prvk.wif(compress);

        if verbose {
            let pubk = prvk.public(compress)?;
            if compress {
                let mut pubk_c = [0x00; NBBY_PUBC];
                pubk_c[..].copy_from_slice(&pubk);
                let pubk_hex = pubk_c.hex_string();
                if separator == SEP_DEFAULT {
                    println!(
                        "{}\n{:42}{}{}{}{}\n{:42}{}{}{}{}\n{}{}{}{}{}",
                        prvk_hex,
                        pubk_c.p2wpkh()?,
                        separator,
                        pubk_hex,
                        separator,
                        wif,
                        pubk_c.segwit_p2wpkh_p2sh()?,
                        separator,
                        pubk_hex,
                        separator,
                        wif,
                        pubk_c.segwit_p2wpkh()?,
                        separator,
                        pubk_hex,
                        separator,
                        wif,
                    );
                } else {
                    println!(
                        "{}\n{}{}{}{}{}\n{}{}{}{}{}\n{}{}{}{}{}",
                        prvk_hex,
                        pubk_c.p2wpkh()?,
                        separator,
                        pubk_hex,
                        separator,
                        wif,
                        pubk_c.segwit_p2wpkh_p2sh()?,
                        separator,
                        pubk_hex,
                        separator,
                        wif,
                        pubk_c.segwit_p2wpkh()?,
                        separator,
                        pubk_hex,
                        separator,
                        wif,
                    );
                }
            } else {
                println!(
                    "{}\n{}{}{}{}{}",
                    prvk_hex,
                    pubk.p2wpkh()?,
                    separator,
                    pubk.hex_string(),
                    separator,
                    wif
                );
            }
        } else {
            println!("{}\n{}", prvk_hex, wif);
        }
        Ok(())
    }

    #[inline]
    fn show_encrypt(&self, pass: &str, compress: bool) -> Result<(), Error> {
        let eprvk = if self.is_empty() {
            pass.generate(compress).map_err(|_| Error::Prvk)?
        } else if self.is_char_boundary(1)
            && (PRE_WIF_C.contains(&self[..1]) || self.starts_with(PRE_WIF_U))
        {
            if self.len() == LEN_WIF_C || self.len() == LEN_WIF_U {
                if !compress {
                    return Err(Error::FlagU);
                }
                let (prvk, compress) = self.decode_wif()?;
                prvk.encrypt(pass, compress)?
            } else {
                return Err(Error::WifKey);
            }
        } else if self.is_hex() {
            if self.len() == 64 {
                let mut prvk = [0x00; 32];
                prvk[..].copy_from_slice(&self.hex_bytes()?);
                prvk.encrypt(pass, compress)?
            } else {
                return Err(Error::HexKey);
            }
        } else {
            return Err(Error::InvArg);
        };
        println!("{}", eprvk);
        Ok(())
    }
}

/// Treat arguments informed by user and act accordingly.
#[doc(hidden)]
pub fn handle_arguments(matches: ArgMatches) -> Result<(), Error> {
    let nothing = "".to_string();
    let sep_temp = SEP_DEFAULT.to_string();
    let compress = !matches.get_one::<bool>("uncompressed").unwrap_or(&false);
    let separator = matches.get_one::<String>("separator").unwrap_or(&sep_temp);
    let verbose = matches.get_one::<bool>("verbose").unwrap_or(&false);
    let pass = matches
        .get_one::<String>("passphrase")
        .ok_or(Error::Parser)?;
    let prv = matches.get_one::<String>("PRIVATE_KEY").unwrap_or(&nothing); // not required

    if !compress && prv.starts_with(PRE_EKEY) {
        return Err(Error::FlagU);
    } else if prv.len() == LEN_EKEY && prv.starts_with(PRE_EKEY) {
        prv.show_decrypt(pass, separator, *verbose)?;
    } else {
        if *verbose {
            eprintln!(
                "{}flag '\x1b[33mverbose\x1b[m' invalid in this context (ignored)",
                WARN
            );

            if separator != SEP_DEFAULT {
                eprintln!(
                    "{}option '\x1b[33mseparator\x1b[m' invalid in this context (ignored)",
                    WARN
                );
            }
        }
        prv.show_encrypt(pass, compress)?;
    }
    Ok(())
}

/// Create the default clap app for the project
#[doc(hidden)]
pub fn init_clap() -> Command {
    Command::new("encrypt38")
        .about(ABOUT)
        .version(crate_version!())
        .arg(
            Arg::new("PRIVATE_KEY")
                .help("Hexadecimal, wif or encrypted private key")
                .value_parser(OsStringValueParser::new().try_map(validate_prvk)),
        )
        .arg(
            Arg::new("separator")
                .help("Specify character (or string) to separate verbose result")
                .requires("verbose")
                .short('s'),
        )
        .arg(
            Arg::new("passphrase")
                .help("Used to encrypt and decrypt the private key (required)")
                .required(true)
                .short('p'),
        )
        .arg(
            Arg::new("uncompressed")
                .help("Encrypted private key to generate uncompressed address")
                .long("uncompressed")
                .short('u')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .help("Show possible address and public key when decrypting")
                .long("verbose")
                .short('v')
                .action(ArgAction::SetTrue),
        )
}

/// Validate if provided string is one of the types of private keys supported.
fn validate_prvk(prvk_os: OsString) -> Result<String, &'static str> {
    let prvk = prvk_os.to_str().unwrap_or("");
    if (prvk.len() == LEN_EKEY && prvk.starts_with(PRE_EKEY))
        || (prvk.len() == 64 && prvk.is_hex())
        || (prvk.is_char_boundary(1)
            && (prvk.len() == LEN_WIF_C && PRE_WIF_C.contains(&prvk[..1])
                || prvk.len() == LEN_WIF_U && prvk.starts_with(PRE_WIF_U)))
    {
        Ok(prvk.to_string())
    } else {
        Err("not an encrypted, hexadecimal or wif private key")
    }
}

/// Tests for functions of this library.
#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes of a double sha256 digest of character 'a'.
    const A_2R: [u8; 32] = [
        0xbf, 0x5d, 0x3a, 0xff, 0xb7, 0x3e, 0xfd, 0x2e, 0xc6, 0xc3, 0x6a, 0xd3, 0x11, 0x2d, 0xd9,
        0x33, 0xef, 0xed, 0x63, 0xc4, 0xe1, 0xcb, 0xff, 0xcf, 0xa8, 0x8e, 0x27, 0x59, 0xc1, 0x44,
        0xf2, 0xd8,
    ];

    /// Bytes of a sha256 and ripemd160 of character 'a'.
    const A_H: [u8; 20] = [
        0x99, 0x43, 0x55, 0x19, 0x9e, 0x51, 0x6f, 0xf7, 0x6c, 0x4f, 0xa4, 0xaa, 0xb3, 0x93, 0x37,
        0xb9, 0xd8, 0x4c, 0xf1, 0x2b,
    ];

    /// Compressed address with secret key of all bytes '0x11'
    const P2WPKH_C_1: &str = "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9";

    /// Compressed address that generated with 'secret' entropy.
    const P2WPKH_C_A: &str = "16JrGhLx5bcBSA34kew9V6Mufa4aXhFe9X";

    /// Compressed address with secret key of all bytes '0x69'.
    const P2WPKH_C_L: &str = "1N7qxowv8SnfdBYhmvpxZxyjsYQDPd88ES";

    /// Uncompressed address generated with entropy of 32 '0x11' bytes.
    const P2WPKH_U_1: &str = "1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a";

    /// Uncompressed address generated with 'secret' entropy.
    const P2WPKH_U_A: &str = "19P1LctLQmH6tuHCRkv8QznNBGBvFCyKxi";

    /// Uncompressed address generated with entropy of 32 '0x69' bytes.
    const P2WPKH_U_L: &str = "17iS4e5ib2t2Bj2UFjPbxSDdmecHNnCAwy";

    /// 'Secret' entropy to generate address.
    const P2WPKH_B: [u8; 32] = [
        0xa9, 0x66, 0xeb, 0x60, 0x58, 0xf8, 0xec, 0x9f, 0x47, 0x07, 0x4a, 0x2f, 0xaa, 0xdd, 0x3d,
        0xab, 0x42, 0xe2, 0xc6, 0x0e, 0xd0, 0x5b, 0xc3, 0x4d, 0x39, 0xd6, 0xc0, 0xe1, 0xd3, 0x2b,
        0x8b, 0xdf,
    ];

    /// Segwit p2wpkh-p2sh address with all secret bytes '0x11'.
    const P2WPKH_P2SH_1: &str = "3PFpzMLrKWsphFtc8BesF3MGPnimKMuF4x";

    /// Segwit p2wpkh-p2sh address with 'secret' entropy.
    const P2WPKH_P2SH_A: &str = "34N3tf5m5rdNhW5zpTXNEJucHviFEa8KEq";

    /// Segwit p2wpkh-p2sh address with all secret bytes '0x69'.
    const P2WPKH_P2SH_L: &str = "35E9BxrEWjgHDFWucazLK5VVxH5oGLRj4g";

    /// Bytes of compressed public key generated with all bytes '0x11'.
    const PUB_C_1: [u8; NBBY_PUBC] = [
        0x03, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61,
        0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07,
        0x58, 0x71, 0xaa,
    ];

    /// Bytes of compressed public key generated with 'P2PKG_B' secret.
    const PUB_C_A: [u8; NBBY_PUBC] = [
        0x02, 0x3c, 0xba, 0x1f, 0x4d, 0x12, 0xd1, 0xce, 0x0b, 0xce, 0xd7, 0x25, 0x37, 0x37, 0x69,
        0xb2, 0x26, 0x2c, 0x6d, 0xaa, 0x97, 0xbe, 0x6a, 0x05, 0x88, 0xcf, 0xec, 0x8c, 0xe1, 0xa5,
        0xf0, 0xbd, 0x09,
    ];

    /// Bytes of compressed public key generated with all bytes '0x69'.
    const PUB_C_L: [u8; NBBY_PUBC] = [
        0x02, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc, 0xb4,
        0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b, 0x1f, 0x99,
        0x57, 0xcc, 0x72,
    ];

    /// Bytes of uncompressed public key generated with all bytes '0x11'.
    const PUB_U_1: [u8; NBBY_PUBU] = [
        0x04, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61,
        0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07,
        0x58, 0x71, 0xaa, 0x38, 0x5b, 0x6b, 0x1b, 0x8e, 0xad, 0x80, 0x9c, 0xa6, 0x74, 0x54, 0xd9,
        0x68, 0x3f, 0xcf, 0x2b, 0xa0, 0x34, 0x56, 0xd6, 0xfe, 0x2c, 0x4a, 0xbe, 0x2b, 0x07, 0xf0,
        0xfb, 0xdb, 0xb2, 0xf1, 0xc1,
    ];

    /// Bytes of uncompressed public key generated with 'P2PKG_B' secret.
    const PUB_U_A: [u8; NBBY_PUBU] = [
        0x04, 0x3c, 0xba, 0x1f, 0x4d, 0x12, 0xd1, 0xce, 0x0b, 0xce, 0xd7, 0x25, 0x37, 0x37, 0x69,
        0xb2, 0x26, 0x2c, 0x6d, 0xaa, 0x97, 0xbe, 0x6a, 0x05, 0x88, 0xcf, 0xec, 0x8c, 0xe1, 0xa5,
        0xf0, 0xbd, 0x09, 0x2f, 0x56, 0xb5, 0x49, 0x2a, 0xdb, 0xfc, 0x57, 0x0b, 0x15, 0x64, 0x4c,
        0x74, 0xcc, 0x8a, 0x48, 0x74, 0xed, 0x20, 0xdf, 0xe4, 0x7e, 0x5d, 0xce, 0x2e, 0x08, 0x60,
        0x1d, 0x6f, 0x11, 0xf5, 0xa4,
    ];

    /// Bytes of uncompressed public key generated with all bytes '0x69'.
    const PUB_U_L: [u8; NBBY_PUBU] = [
        0x04, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc, 0xb4,
        0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b, 0x1f, 0x99,
        0x57, 0xcc, 0x72, 0x9d, 0xd9, 0x76, 0x13, 0x1c, 0x4c, 0x8e, 0x12, 0xab, 0x10, 0x83, 0xca,
        0x06, 0x54, 0xca, 0x5f, 0xdb, 0xca, 0xc8, 0xd3, 0x19, 0x8d, 0xaf, 0x90, 0xf5, 0x81, 0xb5,
        0x91, 0xd5, 0x63, 0x79, 0xca,
    ];

    /// Segwit address generated with secret of all bytes '0x11'
    const SEGW_1: &str = "bc1ql3e9pgs3mmwuwrh95fecme0s0qtn2880lsvsd5";

    /// Segwit address generated with 'secret' number.
    const SEGW_A: &str = "bc1q8gudgnt2pjxshwzwqgevccet0eyvwtswt03nuy";

    /// Segwit address generated with secret of all bytes '0x69'
    const SEGW_L: &str = "bc1qu7nqysur9dr49e4vd9xvguwh5ewzft597d8mc7";

    /// Encrypted secret keys acquired on test vectors of bip-0038.
    const TV_38_ENCRYPTED: [&str; 9] = [
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
        "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
        "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
        "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
        "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
        "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
    ];

    /// Passphrases acquired on test vectors of bip-0038.
    const TV_38_PASS: [&str; 9] = [
        "TestingOneTwoThree",
        "Satoshi",
        "\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}",
        "TestingOneTwoThree",
        "Satoshi",
        "TestingOneTwoThree",
        "Satoshi",
        "MOLON LABE",
        "ΜΟΛΩΝ ΛΑΒΕ",
    ];

    /// Wif private keys from bip-0038 test vectors.
    const TV_38_WIF: [&str; 9] = [
        "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
        "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
        "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
        "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
        "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
        "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2",
        "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH",
        "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8",
        "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D",
    ];

    /// WIF secret key with payload of all bytes '0x11'.
    const WIF_1: &str = "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh";

    /// WIF secret key with payload of 'secret' entropy.
    const WIF_A: &str = "5K6tjEYPunJtSHRbWLSWtYGXmeFW4UJStKb3RUo5VUqQtksHkze";

    /// WIF secret key with payload of all bytes '0x69'.
    const WIF_L: &str = "5JciBbkdYdjKKE9rwZ7c1XscwwcLBbv9aJyeZeWQi2gZnHeiX57";

    /// WIF compressed secret key with all bytes '0x11'.
    const WIC_1: &str = "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp";

    /// WIF compressed secret key of 'secret' entropy.
    const WIC_A: &str = "L2u1KQma7xyx2bVZJUocvV1Yp3R1GKW1FX3Fh3gNphrgTDVqp1sG";

    /// WIF compressed secret key with all bytes '0x69'.
    const WIC_L: &str = "KzkcmnPaJd7mqT47Rnk9XMGRfW2wfo7ar2M2o6Yoe6Rdgbg2bHM9";

    #[test]
    fn test_decode_base58ck() {
        assert_eq!(&"C2dGTwc".decode_base58ck().unwrap(), "a".as_bytes());
        assert_eq!(&"4h3c6RH52R".decode_base58ck().unwrap(), "abc".as_bytes());
    }

    #[test]
    fn test_decode_wif() {
        assert_eq!(WIC_1.decode_wif().unwrap(), ([0x11; 32], true));
        assert_eq!(WIC_L.decode_wif().unwrap(), ([0x69; 32], true));
        assert_eq!(WIF_1.decode_wif().unwrap(), ([0x11; 32], false));
        assert_eq!(WIF_L.decode_wif().unwrap(), ([0x69; 32], false));
        assert_eq!(
            [WIF_L, "a"].concat().decode_wif().unwrap_err(),
            Error::WifKey
        );
        assert_eq!(
            WIC_L.replace("dgbg", "dgdg").decode_wif().unwrap_err(),
            Error::Check
        );
        assert_eq!(["a"; 51].concat().decode_wif().unwrap_err(), Error::WifKey);
        assert_eq!(["a"; 52].concat().decode_wif().unwrap_err(), Error::WifKey);
    }

    #[test]
    fn test_encode_base58ck() {
        assert_eq!("a".as_bytes().encode_base58ck(), "C2dGTwc");
        assert_eq!("abc".as_bytes().encode_base58ck(), "4h3c6RH52R");
    }

    #[test]
    fn test_handle_arguments() {
        assert!(
            handle_arguments(init_clap().get_matches_from(vec!["", "-p", "バンドメイド"])).is_ok()
        );
        assert!(
            handle_arguments(init_clap().get_matches_from(vec!["", "-up", "くるっぽー！"])).is_ok()
        );
        assert!(handle_arguments(init_clap().get_matches_from(vec![
            "",
            TV_38_ENCRYPTED[3],
            "-p",
            TV_38_PASS[3]
        ]))
        .is_ok());
        assert!(handle_arguments(init_clap().get_matches_from(vec![
            "",
            TV_38_WIF[3],
            "-p",
            TV_38_PASS[3]
        ]))
        .is_ok());
    }

    #[test]
    fn test_hash160() {
        assert_eq!("a".as_bytes().hash160(), A_H);
    }

    #[test]
    fn test_hash256() {
        assert_eq!("a".as_bytes().hash256(), A_2R);
    }

    #[test]
    fn test_hex_bytes() {
        assert_eq!("babaca".hex_bytes().unwrap(), [0xba, 0xba, 0xca]);
        assert_eq!("BABACA".hex_bytes().unwrap(), [0xba, 0xba, 0xca]);
    }

    #[test]
    fn test_hex_string() {
        assert_eq!([0xba, 0xba, 0xca].hex_string(), String::from("babaca"));
    }

    #[test]
    fn test_init_clap() {
        assert!(init_clap()
            .try_get_matches_from(vec!["", "-p", TV_38_PASS[3]])
            .is_ok());
        assert!(init_clap()
            .try_get_matches_from(vec!["", TV_38_ENCRYPTED[3], "-p", TV_38_PASS[3]])
            .is_ok());
        assert!(init_clap()
            .try_get_matches_from(vec!["", TV_38_WIF[0], "-p", TV_38_PASS[0]])
            .is_ok());
        assert!(init_clap()
            .try_get_matches_from(vec!["", &["a"; 64].concat(), "-p", TV_38_PASS[0]])
            .is_ok());
        assert!(init_clap().try_get_matches_from(vec![""]).is_err());
        assert!(init_clap().try_get_matches_from(vec!["", "don't"]).is_err());
        assert!(init_clap()
            .try_get_matches_from(vec!["", "something_wrong", "-p", TV_38_PASS[0]])
            .is_err());
        assert!(init_clap()
            .try_get_matches_from(vec![
                "",
                &TV_38_ENCRYPTED[0][..LEN_EKEY - 1],
                "-p",
                TV_38_PASS[0]
            ])
            .is_err());
        assert!(init_clap()
            .try_get_matches_from(vec!["", "5_wrong_uncompressed_wif", "-p", TV_38_PASS[0]])
            .is_err());
        assert!(init_clap()
            .try_get_matches_from(vec!["", "K_wrong_compressed_wif", "-p", TV_38_PASS[0]])
            .is_err());
        assert!(init_clap()
            .try_get_matches_from(vec!["", &["a"; 63].concat(), "-p", TV_38_PASS[0]])
            .is_err());
        assert!(init_clap()
            .try_get_matches_from(vec!["", &["a"; 65].concat(), "-p", TV_38_PASS[0]])
            .is_err());
    }

    #[test]
    fn test_is_hex() {
        assert!("0123456789abcdf".is_hex());
        assert!("ABCDEF".is_hex());
        assert!(!"ghijkl".is_hex());
        assert!(!"'!@#$%&*;:><?".is_hex());
    }

    #[test]
    fn test_p2wpkh() {
        assert_eq!(PUB_C_1.p2wpkh().unwrap(), P2WPKH_C_1);
        assert_eq!(PUB_C_A.p2wpkh().unwrap(), P2WPKH_C_A);
        assert_eq!(PUB_C_L.p2wpkh().unwrap(), P2WPKH_C_L);
        assert_eq!(PUB_U_1.p2wpkh().unwrap(), P2WPKH_U_1);
        assert_eq!(PUB_U_A.p2wpkh().unwrap(), P2WPKH_U_A);
        assert_eq!(PUB_U_L.p2wpkh().unwrap(), P2WPKH_U_L);
        assert_eq!(PUB_C_L[1..].p2wpkh().unwrap_err(), Error::NbPubB);
        assert_eq!(PUB_U_L[1..].p2wpkh().unwrap_err(), Error::NbPubB);
    }

    #[test]
    fn test_public() {
        assert_eq!(P2WPKH_B.public(true).unwrap(), PUB_C_A);
        assert_eq!([0x11; 32].public(true).unwrap(), PUB_C_1);
        assert_eq!([0x69; 32].public(true).unwrap(), PUB_C_L);
        assert_eq!(P2WPKH_B.public(false).unwrap(), PUB_U_A);
        assert_eq!([0x11; 32].public(false).unwrap(), PUB_U_1);
        assert_eq!([0x69; 32].public(false).unwrap(), PUB_U_L);
    }

    #[test]
    fn test_segwit_p2wpkh() {
        assert_eq!(PUB_C_1.segwit_p2wpkh().unwrap(), SEGW_1);
        assert_eq!(PUB_C_A.segwit_p2wpkh().unwrap(), SEGW_A);
        assert_eq!(PUB_C_L.segwit_p2wpkh().unwrap(), SEGW_L);
    }

    #[test]
    fn test_segwit_p2wpkh_p2sh() {
        assert_eq!(PUB_C_1.segwit_p2wpkh_p2sh().unwrap(), P2WPKH_P2SH_1);
        assert_eq!(PUB_C_A.segwit_p2wpkh_p2sh().unwrap(), P2WPKH_P2SH_A);
        assert_eq!(PUB_C_L.segwit_p2wpkh_p2sh().unwrap(), P2WPKH_P2SH_L);
    }

    #[test]
    fn test_show_decrypt() {
        assert!(TV_38_ENCRYPTED[0]
            .show_decrypt(TV_38_PASS[0], SEP_DEFAULT, true)
            .is_ok());
    }

    #[test]
    fn test_show_encrypt() {
        assert_eq!(
            TV_38_WIF[0].show_encrypt("pass", false).unwrap_err(),
            Error::FlagU
        );
        assert!(TV_38_WIF[1].show_encrypt("pass", true).is_ok());
    }

    #[test]
    fn test_validate_prvk() {
        assert!(validate_prvk(OsString::from(WIC_1)).is_ok());
        assert!(validate_prvk(OsString::from(WIC_L)).is_ok());
        assert!(validate_prvk(OsString::from(WIF_1)).is_ok());
        assert!(validate_prvk(OsString::from(WIF_L)).is_ok());
        assert!(validate_prvk(OsString::from(["a"; 64].concat())).is_ok());
        for eprvk in &TV_38_ENCRYPTED {
            assert!(validate_prvk(OsString::from(*eprvk)).is_ok());
        }
        assert!(validate_prvk(OsString::from(&WIC_1[1..])).is_err());
        assert!(validate_prvk(OsString::from(&WIF_1[1..])).is_err());
        assert!(validate_prvk(OsString::from(&WIC_1[..LEN_WIF_C - 1])).is_err());
        assert!(validate_prvk(OsString::from(&WIF_1[..LEN_WIF_U - 1])).is_err());
        assert!(validate_prvk(OsString::from([WIC_1, "1"].concat())).is_err());
        assert!(validate_prvk(OsString::from([WIF_1, "2"].concat())).is_err());
        assert!(validate_prvk(OsString::from(["b"; 63].concat())).is_err());
        assert!(validate_prvk(OsString::from(["x"; 64].concat())).is_err());
        assert!(validate_prvk(OsString::from(["c"; 65].concat())).is_err());
        for eprvk in &TV_38_ENCRYPTED {
            assert!(validate_prvk(OsString::from(&eprvk[1..])).is_err());
        }
        for eprvk in &TV_38_ENCRYPTED {
            assert!(validate_prvk(OsString::from(&eprvk[..LEN_EKEY - 1])).is_err());
        }
        for eprvk in &TV_38_ENCRYPTED {
            assert!(validate_prvk(OsString::from([eprvk, "3"].concat())).is_err());
        }
        assert!(validate_prvk(OsString::from("everything else")).is_err());
    }

    #[test]
    fn test_wif() {
        assert_eq!([0x11; 32].wif(true), WIC_1);
        assert_eq!(P2WPKH_B.wif(true), WIC_A);
        assert_eq!([0x69; 32].wif(true), WIC_L);
        assert_eq!([0x11; 32].wif(false), WIF_1);
        assert_eq!(P2WPKH_B.wif(false), WIF_A);
        assert_eq!([0x69; 32].wif(false), WIF_L);
    }
}
