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

   crypto.Cipher100(data, secret_key, iv, function(err, ciphered_obj) {
      if (err) {
         console.log(err);
         return;
      }

      // Demonstrate normal deciphering
		console.log('=== BEGIN NORMAL DECIPHER100 ===');
		console.log(ciphered_obj);
		console.log();

		crypto.Decipher100(ciphered_obj, function(err, decipher) {
			if (err) {
				console.log(err);
				console.log('=== END NORMAL DECIPHER100 ===');
				return;
			}

			console.log(decipher);
			console.log('=== END NORMAL DECIPHER100 ===');
		});

		// Demonstrate tampering with data
		ciphered_obj.mactag = (ciphered_obj.mactag).replace(/[abcdef]/ig, 'Z');

		console.log();
		console.log('=== BEGIN TAMPERING DECIPHER100 ===');
		console.log(ciphered_obj);
		console.log();

		crypto.Decipher100(ciphered_obj, function(err, decipher) {
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