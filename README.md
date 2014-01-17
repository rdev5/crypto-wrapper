crypto-wrapper
==============

Wrapper module for demonstrating and simplifying Crypto implementation in Node.js

Features:
* UUID
* Sign() and Verify()
* Cipher() and Decipher()
* Hash() selector, HashCrypto(), HashBcrypt(), and VerifyHash() verification selector
* Pack() and Unpack()
* GenerateIV()
* Blocks()
* Encrypt() and Decrypt() / Alias for Cipher+Pack() and Unpack+Decipher()

To generate a public/private keypair:
````
$ openssl genrsa -out examples/keyfiles/sample-privkey.pem 1024
$ openssl rsa -in examples/keyfiles/sample-privkey.pem -pubout > examples/keyfiles/sample-key.pub
````