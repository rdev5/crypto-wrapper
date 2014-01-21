crypto-wrapper
==============
> Wrapper module for demonstrating and simplifying Crypto implementation in Node.js

Configuration:
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

Generating a public/private keypair for signing:
````
$ openssl genrsa -out examples/keyfiles/sample-privkey.pem 1024
$ openssl rsa -in examples/keyfiles/sample-privkey.pem -pubout > examples/keyfiles/sample-key.pub
````

To get started, take a look at the [examples](https://github.com/rdev5/crypto-wrapper/tree/master/examples) included.
