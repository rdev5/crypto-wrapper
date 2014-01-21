/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

var iv_size = 16;
var secret_key = 'MyPassword123';
var salt = crypto.GenerateSalt();
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

      var obj = {
         iv_size: iv_size,
         iv: iv.toString('hex'),
         ciphertext: ciphertext
      };

      var packed_buffer = crypto.Pack(obj);
      var unpacked_obj = crypto.Unpack(packed_buffer);

		console.log('=== BEGIN DATA ===');
		console.log(obj);
		console.log('=== PACKAGE ===');
		console.log(packed_buffer);
		console.log('=== UNPACKED ===');
		console.log(unpacked_obj);
		console.log('=== END DATA ===');
   });
});
