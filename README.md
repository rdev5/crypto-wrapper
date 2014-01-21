# crypto-wrapper
> Wrapper module for demonstrating and simplifying Crypto implementation in Node.js

Version 0.2.0 implements **bcrypt** for the following methods:
* GenerateSalt()
* Hash() and VerifyHash()

## Configuration:
When no configuration is passed to the `CryptoWrapper()` construtor method, the following hard-coded options will be used:
````
var default_options = {
   format: 'hex',
   autopadding: true,

   iv_size: 16,
   key_size: 16,
   key_iterations: 100000,

   salt_rounds: 12,
   seed_length: 40,

   cipher_algorithm: 'aes-128-cbc',
   hash_algorithm: 'sha512',
   signer_algorithm: 'sha1',

   private_key_file: './examples/keyfiles/sample-privkey.pem',
   public_key_file: './examples/keyfiles/sample-key.pub',
};
````

## Generating a public/private keypair for signing:
````
$ openssl genrsa -out examples/keyfiles/sample-privkey.pem 1024
$ openssl rsa -in examples/keyfiles/sample-privkey.pem -pubout > examples/keyfiles/sample-key.pub
````

## Getting Started
To get started, take a look at the [examples](https://github.com/rdev5/crypto-wrapper/tree/master/examples) included.

## References
Before using this library, it is *highly recommended* that you read through the following resources to help establish a more solid understanding of crypto methodologies and best practices.
* [What Are The Essential Properties For Storing Passwords](https://github.com/barrysteyn/node-scrypt#what-are-the-essential-properties-for-storing-passwords)
* [How to Safely Store a Password](http://codahale.com/how-to-safely-store-a-password/)
* [Stronger Key Derivation via Sequential Memory-Hard Functions](http://www.tarsnap.com/scrypt/scrypt.pdf)
* [Bcrypt Evaluation](https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node7.html#SECTION00060000000000000000)
* [The Scrypt Key Derivation Function and Encryption Utility](http://www.tarsnap.com/scrypt.html)

## Disclaimer
This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
