/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

var data = 'Some data I want to hash';
var secret_key = 'MyPassword123';

crypto.Hash100(data, secret_key, function (err, hash) {
	if (err) {
		console.log(err);
		return;
	}

	console.log('Hash: ' + hash);

	crypto.VerifyHash100(hash, secret_key, function (err, verified) {
		if (err) {
			console.log(err);
			return;
		}

		console.log('Verified: ' + verified);
	});
});
