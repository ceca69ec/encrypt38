encrypt38
=========

**Command line tool to encrypt and decrypt bitcoin private keys with
[bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard.**

## Basic usage

```console
$ encrypt38 KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7 -p Satoshi
6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7
```

```console
$ encrypt38 6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7 -p Satoshi
09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae
KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7
```

## Disclaimer

* **Don't trust, verify**

    Compare the results of this tool with others. Verify the implementation (and the tests). Decrypt immediately after an encryption to check the passphrase you *typed* was the one you *wanted*. **Use at your won risk.**

* **Not recommended**

    Use this tool only to decrypt keys you already have. The method of keeping private keys encrypted with bip-0038 standard is [not recommended](https://youtu.be/MbwLVok4gWA?t=2462) anymore (use [mnemonic](https://crates.io/crates/mnemonic39) instead).

* **Pseudo-random number generation**

    This tool use pseudo-random generation ([rand](https://crates.io/crates/rand)) when encrypting using elliptic curve multiplication method (as specified in bip-0038).

## Features

* **Address**

    This tool show the respective address of a decrypted private key in the legacy, segwit-nested and segwit-native formats according to the version prefix of the encrypted private key.

* **Custom separator**

    Customization of the default separator of information when decrypting.

* **Decryption**

    Insert an encrypted private key `6P...` and passphrase do show the private key represented in hexadecimal and the respective address, public key and wif keys.

* **Encryption**

    Insert a private key in the form of hexadecimal numbers or wif key and passphrase to show the encrypted private key.

* **Generation (elliptic curve multiplication method)**

    Insert a passphrase to create an encrypted private key using pseudo-random number generation and elliptic curve multiplication.

* **Uncompressed address**

    This tool is capable of resulting in uncompressed address (mainly for decryption and retro compatibility, *not recommended*).

## Recommendation

* **Build and test**

    Always use the flag `--release` in `cargo` even for running tests. The encryption algorithm is intended to be heavy on cpu so, without the optimizations of a release build, running the tests will be a slow process. With `--release` all tests are done in seconds.
