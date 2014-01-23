/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

var secret_key = 'MyPassword123';
var data = 'Hi John!\n\nIt was nice meeting up with you at CryptoCon this past weekend. Here is my public key:\nABCDEF123\n\nBob';

crypto.GenerateIV(null, function(err, iv) {
   if (err) {
      console.log(err);
      return;
   }

   crypto.Cipher100(data, secret_key, iv, function(err, cipher) {
      if (err) {
         console.log(err);
         return;
      }

      // WARNING: cipher contains hashed_key for demonstration purposes
		console.log('=== BEGIN CIPHER100 ===');
		console.log(cipher);
		console.log('=== END ===');
		console.log();

		var ciphertext_obj = {
			iv: cipher.iv,
			ciphertext: cipher.ciphertext,
			hashed_key: cipher.hashed_key
		};

		var mac_obj = {
			mactag: cipher.mactag,
			mac_key: cipher.mac_key,
		};

		console.log('=== BEGIN DECIPHER100 ===');
		crypto.Decipher100(ciphertext_obj, mac_obj, function(err, decipher) {
			if (err) {
				console.log(err);
				console.log('=== END DECIPHER100 ===');
				return;
			}

			console.log(decipher);
			console.log('=== END DECIPHER100 ===');
		});

		// Demonstrate tampering with data
		mac_obj.mactag = (mac_obj.mactag).replace(/[abcdef]/ig, 'Z');

		console.log();
		console.log('=== BEGIN TAMPERING DECIPHER100 ===');
		console.log(mac_obj);
		console.log();

		crypto.Decipher100(ciphertext_obj, mac_obj, function(err, decipher) {
			if (err) {
				console.log(err);
				console.log('=== END TAMPERING DECIPHER100 ===');
				return;
			}

			console.log(decipher);
			console.log('=== END TAMPERING DECIPHER100 ===');
		});
   });
});