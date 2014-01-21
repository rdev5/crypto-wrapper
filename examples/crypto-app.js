/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

var secret_key = 'MyPassword123';
var salt = crypto.GenerateSalt();
var data = 'Hi John!\n\nIt was nice meeting up with you at CryptoCon this past weekend. Here is my public key:\nABCDEF123\n\nBob';

// Implementation guidelines:
// 1. Send packed_string and packed_sig
// 2. Verify packed_string received against packed_sig
// 3. If valid signature, decrypt

crypto.Encrypt(data, secret_key, salt, function(err, packed_string) {
	if (err) {
		console.log(err);
		return;
	}

	var packed_sig = crypto.Sign(packed_string);

	if (crypto.VerifySignature(packed_string, packed_sig)) {
		crypto.Decrypt(packed_string, secret_key, salt, function(err, plaintext) {
			if (err) {
				console.log(err);
				return;
			}

			console.log('=== BEGIN DATA ===');
			console.log(data);
			console.log('=== ENCRYPT ===');
			console.log(packed_string);
			console.log('=== SIGNATURE ===');
			console.log(packed_sig);
			console.log('=== DECRYPT ===');
			console.log(plaintext);
			console.log('=== SIGNATURE VERIFY ===');
			console.log('Package signature verified: ' + crypto.VerifySignature(packed_string, packed_sig));
			console.log('=== END DATA ===');
		});
	} else {
		console.log('Invalid package signature');
	}
});
