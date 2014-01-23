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

		crypto.Decipher100(cipher.ciphertext, cipher.hashed_key, cipher.iv, function(err, decipher) {
			if (err) {
				console.log(err);
				return;
			}

			console.log('=== BEGIN DECIPHER100 ===');
			console.log(decipher);
			console.log('=== END ===');
		});
   });
});