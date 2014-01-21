/* jslint node: true */
'use strict';

var fs = require('fs');
var crypto = require('crypto');
var bcrypt = require('bcrypt');

var INTEGER_LEN = 4;

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

CryptoWrapper.prototype.Cipher = function(plaintext, secret_key, salt, iv, callback) {
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

CryptoWrapper.prototype.Decipher = function(ciphertext, secret_key, salt, iv, callback) {
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
CryptoWrapper.prototype.Encrypt = function(data, secret_key, salt, callback) {
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

      self.Cipher(data, secret_key, salt, iv, function(err, ciphertext) {
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
CryptoWrapper.prototype.Decrypt = function(packedBuffer, secret_key, salt, callback) {
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

   self.Decipher(ciphertext, secret_key, salt, iv, function(err, plaintext) {
      if (err) {
         return callback(err);
      }

      callback(null, plaintext);
   });
};

module.exports = CryptoWrapper;
