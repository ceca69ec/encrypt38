encrypt38
=========

**Implementation of [bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) in rust for use on command line interface.**

## Disclaimer

* **Don't trust, verify**
 - Compare the results of this tool with others. Verify the implementation (and the tests). Decrypt immediately after an encryption to check the passphrase you *typed* was the one you *wanted*. **Use at your won risk.**
* **Not recommended**
 - Use this tool only to decrypt keys you already have. The method of keeping private keys encrypted with bip-0038 standard is [not recommended](https://youtu.be/MbwLVok4gWA?t=2462) anymore (use [mnemonic](https://github.com/ceca69ec/mnemonic39) instead).
* **Pseudo-random number generation**
 - This tool use pseudo-random generation ([rand](https://github.com/rust-random/rand)) when encrypting using elliptic curve multiplication method (as specified in  bip-0038).

## Features

* **Address**
 - This tool show the respective address of a decrypted private key in the legacy, segwit-nested and segwit-native formats according to the version prefix of the encrypted private key.
* **Custom separator**
 - Customization of the default separator of information on result.
* **Decryption**
 - Insert an encrypted private key `6P...` and passphrase do show the private key represented in hexadecimal and the respective address and wif keys.
* **Encryption**
 - Insert a private key in the form of hexadecimal numbers or wif key and passphrase to show the encrypted private key.
* **Encryption (using elliptic curve multiplication)**
 - Insert a passphrase to generate an encrypted private key using pseudo-random number generation and elliptic curve multiplication (*not recommended*).
* **Uncompressed address**
 - This tool is capable of resulting in uncompressed address (mainly for decryption and retro compatibility, *not recommended*).

## Recommendation

* **Build and test**
 - Always use the flag `--release` in `cargo` even for running tests. The encryption algorithm is intended to be heavy on cpu so, without the optimizations of a release build, running the tests will be a slow process. With `--release` all tests are done in seconds.

## Suggestion for generating hexadecimal private key

* **Disclaimer**
 - This is just one (and maybe not the best one) of various methods that can be used to generate random numbers. Again: use at your won risk.
* **What you need**
 - A `d20` (a dice with 20 faces, very common on rpg).
* **Values**
 - **1-9**: `use the value`.
 - **10**: `a`
 - **11**: `b`
 - **12**: `c`
 - **13**: `d`
 - **14**: `e`
 - **15**: `f`
 - **16**: `0 (zero)`
 - **17-20**: `throw again`
* **Method**
 - Throw the dice and type the value as described above until you have 64 hexadecimal numbers.
 - Use those 64 numbers in the this tool with a passphrase and it will generate the encrypted private key.
 - Always use a live Linux-gnu distribution loaded to the ram (*toram* on Debian and *copytoram* on Arch) with all hard drives and any type of internet connection disabled. **Don't keep the hexadecimal private key in any form**
