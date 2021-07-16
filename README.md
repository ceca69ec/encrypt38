encrypt38
=========

**Command line tool to encrypt and decrypt bitcoin private keys with
[bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard.**

## Basic usage

```console
$ encrypt38 -p Satoshi KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7
6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7
```

```console
$ encrypt38 -p Satoshi 6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7
09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae
KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7
```

## Disclaimer

* **Don't trust, verify**

    Compare the results of this tool with others. Verify the implementation (and the tests). Decrypt
 immediately after an encryption to check the passphrase you *typed* was the one you *wanted*. 
**Use at your won risk.**

* **Not recommended**

    Use this tool only to decrypt keys you already have. The method of keeping private keys 
encrypted with bip-0038 standard is [not recommended](https://youtu.be/MbwLVok4gWA?t=2462) anymore 
(use [mnemonic](https://crates.io/crates/mnemonic39) instead).

## Features

* **Address**

    This tool show the respective address of a decrypted private key in the legacy, segwit-nested 
and segwit-native formats according to the version prefix of the encrypted private key.

* **Custom separator**

    Customization of the default separator of information when decrypting.

* **Decryption**

    Insert an encrypted private key `6P...` and passphrase do show the private key represented in 
hexadecimal and the respective address, public key and wif keys.

* **Encryption**

    Insert a private key in the form of hexadecimal numbers or wif key and passphrase to show the 
encrypted private key.

* **Generation (elliptic curve multiplication method)**

    Insert a passphrase to create an encrypted private key using pseudo-random number generation and
 elliptic curve multiplication.

* **Uncompressed address**

    This tool is capable of resulting in uncompressed address (mainly for decryption and retro 
compatibility, *not recommended*).

## Help

```bash
encrypt38 1.1.3
Insert encrypted, hexadecimal or wif private key and passphrase to decrypt or
encrypt accordingly. Insert only passphrase to create an encrypted private key
using elliptic curve multiplication (and pseudo-random number generation).

USAGE:
    encrypt38 [FLAGS] [OPTIONS] -p <passphrase> [PRIVATE_KEY]

FLAGS:
    -h, --help            Prints help information
    -u, --uncompressed    Encrypted private key to generate uncompressed address
    -V, --version         Prints version information
    -v, --verbose         Show possible address and public key when decrypting

OPTIONS:
    -p <passphrase>        Used to encrypt and decrypt the private key (required)
    -s <separator>         Specify character (or string) to separate verbose result

ARGS:
    <PRIVATE_KEY>    Hexadecimal, wif or encrypted private key
```
