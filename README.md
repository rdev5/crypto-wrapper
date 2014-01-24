# crypto-wrapper
> Wrapper module for demonstrating and simplifying Crypto implementation in Node.js<br />

### Have feedback or suggestions? Want to talk about crypto?
> Log on to `irc.freenode.net` and join the `##crypto` crowd!

The preferred method for flagging something that needs attention would be to [Open a New Issue](https://github.com/rdev5/crypto-wrapper/issues) and adding an appropriate **Label**.

### What's New
**Version 1.0.0** implements **scrypt** for the following methods:
* `Cipher100()` and `Decipher100()` (forces message authentication on decipher)
* `Hash100()` and `VerifyHash100()` (built-in message authentication)

**Version 0.2.0** implements **bcrypt** and **PBKDF2** for the following methods:
* `GenerateSalt020()`
* `Hash020()` and `VerifyHash020()`
* `Cipher020()` and `Decipher020()` (no message authentication)
* `Encrypt020()` and `Decrypt020()` helper methods (no message authentication)

## Dependencies:
* [node-scrypt](https://github.com/barrysteyn/node-scrypt)
* [node.bcrypt.js](https://github.com/ncb000gt/node.bcrypt.js/)
* [lodash](https://github.com/lodash/lodash)

## Configuration:
When no configuration is passed to the `CryptoWrapper()` construtor method, the following hard-coded options will be used:
````
var default_options = {
   format: 'hex',
   autopadding: true,

   iv_size: 16,
   key_size: 16,
   key_iterations: 100000,
   mac_key_size: 64,

   salt_rounds: 12,
   seed_length: 40,

   cipher_algorithm: 'aes-128-cbc',
   mac_algorithm: 'sha512',
   hash_algorithm: 'sha512',
   signer_algorithm: 'sha1',

   private_key_file: './examples/keyfiles/sample-privkey.pem',
   public_key_file: './examples/keyfiles/sample-key.pub',

	// scrypt.params()
	// { N: 16, r: 1, p: 1 }		// test vector 1
	// { N: 1024, r: 8, p: 16 }	// test vector 2
	// { N: 16384, r: 8, p: 1 }	// test vector 3
	// { N: 1048576, r: 8, p: 1 }	// test vector 4 (experimental)
	scrypt_params: { N: 16384, r: 8, p: 1 },

	scrypt_kdf_config: {
		saltEncoding: 'buffer',
		keyEncoding: 'ascii',
		outputEncoding: 'buffer',
		defaultSaltSize: 256,
		outputLength: 80 // key_size + mac_key_size
	},
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
* [Crypto Implementation (DRAFT)](https://github.com/rdev5/crypto-wrapper/wiki/Crypto-Implementation-%28DRAFT%29)
* [What Are The Essential Properties For Storing Passwords](https://github.com/barrysteyn/node-scrypt#what-are-the-essential-properties-for-storing-passwords)
* [How to Safely Store a Password](http://codahale.com/how-to-safely-store-a-password/)
* [Stronger Key Derivation via Sequential Memory-Hard Functions](http://www.tarsnap.com/scrypt/scrypt.pdf)
* [Bcrypt Evaluation](https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node7.html#SECTION00060000000000000000)
* [The Scrypt Key Derivation Function and Encryption Utility](http://www.tarsnap.com/scrypt.html)

## Disclaimer
> Use of the service is at your own risk.

THE SERVICE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL I BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SERVICE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
