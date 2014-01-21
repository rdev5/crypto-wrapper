/* jslint node: true */
'use strict';

var fs = require('fs');
var crypto = require('crypto');
var bcrypt = require('bcrypt');
var uuid = require('node-uuid');

var INTEGER_LEN = 4;

var default_options = {
   format: 'hex',
   iv_size: 16,
   keylen: 16,

   salt_rounds: 10,
   iterations: 10000,

   autopadding: true,

   algorithm: 'aes-128-cbc',
   hash_algorithm: 'sha512',

   signer: 'sha1',

   secret_key: 'CHANGETHIS',
   salt: 'CHANGETHIS',

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

CryptoWrapper.prototype.Sign = function(data) {
	var self = this;

	return crypto.createSign(self.options.signer).update(data).sign( fs.readFileSync(self.options.private_key_file), self.options.format );
};

CryptoWrapper.prototype.Verify = function(data, signature) {
	var self = this;

	try {
		var signature_valid = crypto.createVerify(self.options.signer).update(data).verify( fs.readFileSync(self.options.public_key_file), signature, self.options.format );
		return signature_valid;
	} catch (e) {
		// TypeError: Invalid hex string
		return false;
	}
};

// Hash selector
CryptoWrapper.prototype.Hash = function(data, iterations) {
	var self = this;

   if (!iterations) {
      iterations = self.options.iterations;
   }

   // return self.HashCrypto(data, iterations);
   return self.HashBcrypt(data, iterations);
};

CryptoWrapper.prototype.HashBcrypt = function(data, iterations) {
	var self = this;
	
   return bcrypt.hashSync( data, bcrypt.genSaltSync( self.options.salt_rounds, iterations ) );
};

// Hash verification selector
CryptoWrapper.prototype.VerifyHash = function(data, hash) {
	var self = this;

   // return self.HashCrypto(data) === hash;
   return bcrypt.compareSync(data, hash);
};

CryptoWrapper.prototype.ShuffleString = function(value) {
	var self = this;

   var a = value.split(""),
      n = a.length;

   for(var i = n - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var tmp = a[i];
      a[i] = a[j];
      a[j] = tmp;
   }

   return a.join("");
};

CryptoWrapper.prototype.RandomString = function(len, possible) {
	var self = this;

   var text = "";

   if (!possible) {
      possible = "$#*ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   }

   for( var i=0; i < len; i++ )
   text += possible.charAt(Math.floor(Math.random() * possible.length));

   return text;
};

CryptoWrapper.prototype.GenerateKey = function() {
	var self = this;

   var key = uuid.v4();
   key = key.replace(/\-/g, self.RandomString(1));

   return key;
};

CryptoWrapper.prototype.GenerateSalt = function() {
	var self = this;

   var salt = uuid.v4();
   salt = salt.replace(/\-/g, self.RandomString(1));

   return salt;
};

CryptoWrapper.prototype.GenerateIV = function(iv_size, callback) {
	var self = this;

   crypto.randomBytes(iv_size, function(err, iv) {
      if (err) {
         return callback(err);
      }

      callback(null, iv);
   });
};

CryptoWrapper.prototype.Blocks = function(buffer, size) {
	var self = this;

   var len = buffer.length;
   var rounds = Math.ceil(len / size);

   var blocks = [];
   for (var i = 1; i <= rounds; i++) {
      var block = new Buffer(size);
      var start = (i - 1) * size;

      buffer.copy(block, 0, start, start+size);
      blocks.push(block);
   }

   return blocks;
};

CryptoWrapper.prototype.HashCrypto = function(data, iterations) {
	var self = this;

   for (var i = 1; i <= iterations; i++) {
      var hasher = crypto.createHash(self.options.hash_algorithm);
      hasher.update(data);
      data = hasher.digest(self.options.format);
   }

   return data;
};

CryptoWrapper.prototype.Cipher = function(plaintext, secret_key, salt, iv, callback) {
	var self = this;

   crypto.pbkdf2(secret_key, salt, self.options.iterations, self.options.keylen, function(err, key) {
      if (err) {
         return callback(err);
      }

      var cipher = crypto.createCipheriv(self.options.algorithm, key, iv);
      cipher.setAutoPadding(self.options.autopadding);

      var ciphertext = cipher.update(plaintext, 'utf8', self.options.format);
      ciphertext += cipher.final(self.options.format);

      callback(null, ciphertext);
   });
};

CryptoWrapper.prototype.Decipher = function(ciphertext, secret_key, salt, iv, callback) {
	var self = this;

   crypto.pbkdf2(secret_key, salt, self.options.iterations, self.options.keylen, function(err, key) {
      if (err) {
         return callback(err);
      }

      var decipher = crypto.createDecipheriv(self.options.algorithm, key, iv);
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
      return null;
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
 */
CryptoWrapper.prototype.Encrypt = function(data, callback) {
	var self = this;

   if (data === null) {
      return callback(null, null);
   }

   self.GenerateIV(self.options.iv_size, function(err, iv) {
      if (err) {
         return callback(err);
      }

      self.Cipher(data, self.options.secret_key, self.options.salt, iv, function(err, ciphertext) {
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
 * @param buffer packedBuffer - must be properly packed using Pack()
 */
CryptoWrapper.prototype.Decrypt = function(packedBuffer, callback) {
	var self = this;

   var unpackedObj = self.Unpack(new Buffer(packedBuffer, self.options.format));
   var iv_size = unpackedObj.iv_size;
   var iv = new Buffer(unpackedObj.iv, self.options.format);
   var ciphertext = new Buffer(unpackedObj.ciphertext, self.options.format);

   self.Decipher(ciphertext, self.options.secret_key, self.options.salt, iv, function(err, plaintext) {
      if (err) {
         return callback(err);
      }

      callback(null, plaintext);
   });
};

module.exports = CryptoWrapper;
