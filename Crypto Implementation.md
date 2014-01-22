**Version 1.0** (January 22, 2014)

## Purpose
The purpose of this project is to stay up to date on the latest best practices in cryptography while streamlining implementation by providing developers with quick references and code examples.

Many times developers avoid crypto altogether because they've been admonished time and time again "you're doing it wrong." This document is aimed at those as an aid to help them "do it right."

## Objectives
1. Clearly and concisely establish best practices for crypto implementation
2. Demonstrate the proper way to cipher, hash, sign, and apply message authentication
3. Garner feedback and actively maintain methodologies and procedures outlined in this document

## Application
Version 1.0 - The methodologies outlined in this version apply to the encryption and decryption of text strings containing sensitive information (i.e. passwords, messages, etc).

## Parameters
* **Plaintext** - A string containing sensitive information you wish to encrypt
* **Passphrase** - Your master key for encryption and decryption
* **Key Derivation Function (KDF)** - Master key hashing used to mitigate weak passphrases
* **Salt** - A non-secret KDF parameter used to mitigate dictionary attacks on a *secret key*
* **Initialization Vector (IV)** - A one-time use cryptographically strong random value used to begin a cipher
* **Message Authentication Code (MAC)** - A checksum used to manually verify the integrity and origin of a ciphertext

## Procedures
Developers work in various languages and are sometimes providentially hindered from using libraries for one reason or another. The following provides some general guidelines for implementing crypto properly should you be left to writing a library on your own.

### Ciphering (Encryption)
The following procedure for ciphering assumes the use of **AES-128-CBC**.

1. **Generate a hashed master key.** Use a Key Derivation Function to derive the hashed value of your master key. Some KDFs (such as the variable length [Scrypt](https://github.com/barrysteyn/node-scrypt#kdf) or fixed length [Bcrypt](https://github.com/ncb000gt/node.bcrypt.js/#api)) will generate a *salt* for you during hashing. Otherwise, you will need to provide one.

2. **Generate keys for ciphering and MAC.** Deriving two (2) separate keys using your *hashed master key* from Step 1 is recommended before ciphering and creating a message authentication code. One method for doing this is to use **HKDF-Expand** as running KDF multiple times is not recommend for performance reasons. Alternatively, if your KDF has a configurable output size (like Scrypt), you may opt to extract the first half of your *hashed master key* as the key for ciphering and extract the second half for generating the MAC.

3. **Generate a unique Initialization Vector.** A new Initialization Vector (or IV for short) must be generated each time you run a cipher, even if you are encrypting the same message twice. To achieve *semantic security*, under no circumstances should a cipher re-use an IV.

4. **Generate ciphertext.** Encrypt your plaintext using the *key for ciphering* from Step 2 and the *Initialization Vector* from Step 3. This will produce your *ciphertext*.

5. **Generate message authentication code.** Proceed to generate a message authentication code (or MAC for short) for the *ciphertext* from Step 4 using the *key for generating the MAC* from Step 3. One method for doing this is to use **Hash-based Message Authentication Code (HMAC)**.

6. **Store the ciphertext with its message authentication code.**

## References
* [Semantic security - Wikipedia](http://en.wikipedia.org/wiki/Semantic_security)
* [Bcrypt as a KDF - StackExchange](http://security.stackexchange.com/a/10985)
* [Understanding the use of IVs - StackExchange](http://crypto.stackexchange.com/a/735)
* [Initialization vector - Wikipedia](http://en.wikipedia.org/wiki/Initialization_vector)
* [Key derivation function - Wikipedia](http://en.wikipedia.org/wiki/Key_derivation_function)
* [Message authentication code - Wikipedia](http://en.wikipedia.org/wiki/Message_authentication_code)
* [Oracle machine - Wikipedia](http://en.wikipedia.org/wiki/Oracle_machine)