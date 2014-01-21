/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

var secret_key = 'MyPassword123';
var salt = 'MySalt890';
var data = 'Hi John!\n\nIt was nice meeting up with you at CryptoCon this past weekend. Here is my public key:\nABCDEF123\n\nBob';

crypto.GenerateIV(null, function(err, iv) {
   if (err) {
      console.log(err);
      return;
   }

   crypto.Cipher(data, secret_key, salt, iv, function(err, ciphertext) {
      if (err) {
         console.log(err);
         return;
      }

      crypto.Decipher(ciphertext, secret_key, salt, iv, function(err, plaintext) {

			console.log('=== BEGIN DATA ===');
			console.log(data);
			console.log('=== CIPHER ===');
			console.log('IV: ' + iv.toString('hex'));
			console.log('Ciphertext: ' + ciphertext);
			console.log('=== DECIPHER ===');
			console.log(plaintext);
			console.log('=== END DATA ===');

      });
   });
});