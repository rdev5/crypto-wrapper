/* jslint node: true */
'use strict';

var fs = require('fs');
var crypto = require('crypto');
var bcrypt = require('bcrypt');
var scrypt = require('scrypt');
var _ = require('lodash');

var INTEGER_LEN = 4;

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

function CryptoWrapper(options) {
   if (this instanceof CryptoWrapper) {
      this.options = options ? options : default_options;
   } else {
      return (new CryptoWrapper(options));
   }
}

CryptoWrapper.prototype.GenerateSalt = function(salt_rounds, seed_length) {
	var self = this;

   if (!salt_rounds) salt_rounds = self.options.salt_rounds;
   if (!seed_length) seed_length = self.options.seed_length;

   var salt = bcrypt.genSaltSync( salt_rounds, seed_length );

   return salt;
};

CryptoWrapper.prototype.GenerateIV = function(iv_size, callback) {
	var self = this;

	if (isNaN(parseInt(iv_size, 10))) iv_size = self.options.iv_size;

   crypto.randomBytes(iv_size, function(err, iv) {
      if (err) {
         return callback(err);
      }

      callback(null, iv);
   });
};

CryptoWrapper.prototype.Sign = function(data) {
	var self = this;

	return crypto.createSign(self.options.signer_algorithm).update(data).sign( fs.readFileSync(self.options.private_key_file), self.options.format );
};

CryptoWrapper.prototype.VerifySignature = function(data, signature) {
	var self = this;

	try {
		var signature_valid = crypto.createVerify(self.options.signer_algorithm).update(data).verify( fs.readFileSync(self.options.public_key_file), signature, self.options.format );
		return signature_valid;
	} catch (e) {
		// TypeError: Invalid hex string in signature
		return false;
	}
};

CryptoWrapper.prototype.Hash = function(data, salt_rounds, seed_length) {
	var self = this;
	
   return bcrypt.hashSync( data, self.GenerateSalt(salt_rounds, seed_length) );
};

CryptoWrapper.prototype.VerifyHash = function(data, hash) {
	var self = this;

   return bcrypt.compareSync(data, hash);
};

CryptoWrapper.prototype.dev_random = function(size, callback) {
	var self = this;

	var dev_random;
	var stream = fs.createReadStream('/dev/random', {start: 1, end: self.options.key_size });

	stream.on('data', function(chunk) {
		dev_random += chunk;
	});

	stream.on('end', function() {
		return callback(null, dev_random);
	});
};

CryptoWrapper.prototype.Cipher100 = function(plaintext, secret_key, iv, callback) {
	var self = this;

	try {
		_.assign(scrypt.kdf.config, self.options.scrypt_kdf_config);

		scrypt.kdf(secret_key, self.options.scrypt_params, function(err, obj) {
			if (err) {
				return callback(err);
			}

			var hashed_key = new Buffer(self.options.key_size);
			var mac_key = new Buffer(self.options.mac_key_size);

			(obj.hash).copy(hashed_key, 0, 0, self.options.key_size);
			(obj.hash).copy(mac_key, 0, self.options.key_size, self.options.mac_key_size);

			try {
				var cipher = crypto.createCipheriv(self.options.cipher_algorithm, hashed_key, iv);
				cipher.setAutoPadding(self.options.autopadding);

				var ciphertext = cipher.update(plaintext, 'utf8', self.options.format);
				ciphertext += cipher.final(self.options.format);

				var mactag = crypto.createHmac(self.options.mac_algorithm, mac_key).update(ciphertext).digest(self.options.format);

				callback(null, { iv: iv.toString(self.options.format), ciphertext: ciphertext, hashed_key: hashed_key.toString(self.options.format), mactag: mactag, mac_key: mac_key.toString(self.options.format) });
			} catch(e) {
				console.log(e);
				return callback(e);
			}

		});
	} catch(e) {
		return callback(e);
	}
};

CryptoWrapper.prototype.Decipher100 = function(ciphered_obj, callback) {
	var self = this;

	try {
		var iv = new Buffer(ciphered_obj.iv, self.options.format);
		var ciphertext = new Buffer(ciphered_obj.ciphertext, self.options.format);
		var hashed_key = new Buffer(ciphered_obj.hashed_key, self.options.format);

		var mactag = new Buffer(ciphered_obj.mactag, self.options.format);
		var mac_key = new Buffer(ciphered_obj.mac_key, self.options.format);

		var verify_mactag = crypto.createHmac(self.options.mac_algorithm, mac_key).update(ciphertext.toString(self.options.format)).digest(self.options.format);

		if (mactag.toString(self.options.format) !== verify_mactag) {
			throw new Error('Invalid message authentication code');
		}

		var decipher = crypto.createDecipheriv(self.options.cipher_algorithm, hashed_key, iv);
		decipher.setAutoPadding(self.options.autopadding);

		var plaintext = decipher.update(ciphertext, self.options.format, 'utf8');
		plaintext += decipher.final('utf8');

		callback(null, plaintext);
	} catch(e) {
		return callback(e);
	}
};

CryptoWrapper.prototype.Cipher020 = function(plaintext, secret_key, salt, iv, callback) {
	var self = this;

	if (!iv) {
		return callback('IV required');
	}

	if (!salt) salt = self.GenerateSalt();

   crypto.pbkdf2(secret_key, salt, self.options.key_iterations, self.options.key_size, function(err, key) {
      if (err) {
         return callback(err);
      }

      var cipher = crypto.createCipheriv(self.options.cipher_algorithm, key, iv);
      cipher.setAutoPadding(self.options.autopadding);

      var ciphertext = cipher.update(plaintext, 'utf8', self.options.format);
      ciphertext += cipher.final(self.options.format);

      callback(null, ciphertext);
   });
};

CryptoWrapper.prototype.Decipher020 = function(ciphertext, secret_key, salt, iv, callback) {
	var self = this;

   crypto.pbkdf2(secret_key, salt, self.options.key_iterations, self.options.key_size, function(err, key) {
      if (err) {
         return callback(err);
      }

      var decipher = crypto.createDecipheriv(self.options.cipher_algorithm, key, iv);
      decipher.setAutoPadding(self.options.autopadding);

      var plaintext = decipher.update(ciphertext, self.options.format, 'utf8');
      plaintext += decipher.final('utf8');

      if (callback !== undefined) {
         callback(null, plaintext);
      }

      return plaintext;
   });
};

/*
 * @param object unpackedObj = { int iv_size, string iv, string ciphertext } (implements self.options.format)
 * @return encoded buffer packedBuffer (implements self.options.format)
 */
CryptoWrapper.prototype.Pack = function(unpackedObj) {
	var self = this;

   if (typeof unpackedObj !== 'object') {
      return null;
   }

   /*
    * @param object unpackedObj
    * @requires buffer iv_size (presently enforces self.options.iv_size)
    * @requires buffer iv
    * @requires buffer ciphertext
    */
   if (unpackedObj.iv_size === undefined || unpackedObj.iv_size !== self.options.iv_size) {
      return null;
   }

   if (unpackedObj.iv === undefined) {
      return null;
   }

   if (unpackedObj.ciphertext === undefined) {
      return null;
   }

   // Pack iv_size buffer using BIG_ENDIAN
   var n_buffer = new Buffer(INTEGER_LEN);
   n_buffer.writeUInt32BE(unpackedObj.iv_size, 0);

   // Pack iv buffer
   var i_buffer = new Buffer(unpackedObj.iv, self.options.format);

   // Pack ciphertext buffer
   var c_buffer = new Buffer(unpackedObj.ciphertext, self.options.format);

   var packedBuffer = new Buffer(n_buffer.length + i_buffer.length + c_buffer.length);
   n_buffer.copy(packedBuffer, 0, 0, n_buffer.length);
   i_buffer.copy(packedBuffer, n_buffer.length, 0, i_buffer.length);
   c_buffer.copy(packedBuffer, n_buffer.length + i_buffer.length, 0, c_buffer.length);

   return packedBuffer.toString(self.options.format);
};

/*
 * @param buffer packedBuffer [ iv_size + iv + ciphertext ]
 * @return object unpackedObj = { iv_size: buffer, iv: buffer, ciphertext: buffer } (implements self.options.format)
 */
CryptoWrapper.prototype.Unpack = function(packedBuffer) {
	var self = this;

   if (!Buffer.isBuffer(packedBuffer)) {
		var try_buffer = new Buffer(packedBuffer, self.options.format);
		if (Buffer.isBuffer(try_buffer)) {
			packedBuffer = try_buffer;
		} else {
			return false;
		}
   }

   var unpackedObj = {};

   // Unpack iv_size using BIG_ENDIAN
   var n_buffer = new Buffer(INTEGER_LEN);
   packedBuffer.copy(n_buffer, 0, 0, INTEGER_LEN);
   unpackedObj.iv_size = n_buffer.readUInt32BE(0);

   // Unpack iv
   var i_buffer = new Buffer(unpackedObj.iv_size);
   packedBuffer.copy(i_buffer, 0, INTEGER_LEN, (INTEGER_LEN + unpackedObj.iv_size));
   unpackedObj.iv = i_buffer.toString(self.options.format);

   // Unpack ciphertext
   var c_buffer = new Buffer(packedBuffer.length - (INTEGER_LEN + unpackedObj.iv_size));
   packedBuffer.copy(c_buffer, 0, (INTEGER_LEN + unpackedObj.iv_size), packedBuffer.length);
   unpackedObj.ciphertext = c_buffer.toString(self.options.format);

   return unpackedObj;
};

/*
 * Crypt.Encrypt()
 * - Generates cryptographically strong psuedo-random initialization vector (IV)
 * - Use password based key encryption
 * - Prepend ciphertext with size and value of IV
 *
 * @return buffer Packed(iv_size, iv, ciphertext)
 */
CryptoWrapper.prototype.Encrypt020 = function(data, secret_key, salt, callback) {
	var self = this;

   if (data === null) {
      return callback(null, null);
   }

	if (!secret_key) {
		return callback('Secret key required');
	}

	if (!salt) {
		return callback('Salt required');
	}

   self.GenerateIV(self.options.iv_size, function(err, iv) {
      if (err) {
         return callback(err);
      }

      self.Cipher020(data, secret_key, salt, iv, function(err, ciphertext) {
         if (err) {
            return callback(err);
         }

         callback(null, self.Pack({
            iv_size: self.options.iv_size,
            iv: iv.toString(self.options.format),
            ciphertext: ciphertext.toString(self.options.format)
         }));
      });
   });
};

/*
 * Crypt.Decrypt()
 * @param buffer Packed(iv_size, iv, ciphertext)
 */
CryptoWrapper.prototype.Decrypt020 = function(packedBuffer, secret_key, salt, callback) {
	var self = this;

   var unpackedObj = self.Unpack(new Buffer(packedBuffer, self.options.format));
   if (!unpackedObj) {
		return callback('Packed buffer required');
   }

	if (!secret_key) {
		return callback('Secret key required');
	}

	if (!salt) {
		return callback('Salt required');
	}

   var iv_size = unpackedObj.iv_size;
   var iv = new Buffer(unpackedObj.iv, self.options.format);
   var ciphertext = new Buffer(unpackedObj.ciphertext, self.options.format);

   self.Decipher020(ciphertext, secret_key, salt, iv, function(err, plaintext) {
      if (err) {
         return callback(err);
      }

      callback(null, plaintext);
   });
};

module.exports = CryptoWrapper;
	