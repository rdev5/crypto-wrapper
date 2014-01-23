/* jslint node: true */
'use strict';

var scrypt = require('scrypt');
var _ = require('lodash');

var secret_key = 'MyPassword123';

var options = {

	params_config: {
		maxtime: 0.1,
		// maxmem: 0,
		// maxmemfrac: 0.5
	},

	hash_config: {
		keyEncoding: 'ascii',
		outputEncoding: 'hex'
	},

	verify_config: {
		keyEncoding: 'ascii',
		hashEncoding: 'hex'
	},

	kdf_config: {
		saltEncoding: 'buffer',
		keyEncoding: 'ascii',
		outputEncoding: 'hex',
		defaultSaltSize: 32,
		outputLength: 16
	},

	// kdf_params
	// { N: 16, r: 1, p: 1 }		// test vector 1
	// { N: 1024, r: 8, p: 16 }	// test vector 2
	// { N: 16384, r: 8, p: 1 }	// test vector 3
	// { N: 1048576, r: 8, p: 1 }	// test vector 4 (experimental)
	kdf_params: { N: 16384, r: 8, p: 1 }
};

// params (sync)
try {
	var params = scrypt.params(options.params_config.maxtime);
	_.assign(scrypt.params.config, options.params_config);
	console.log('Configuration: ' + JSON.stringify(scrypt.params.config));
} catch(e) {
	console.log(e);
	process.exit(1);
}

// hash (sync)
try {
	_.assign(scrypt.hash.config, options.hash_config);
	var hash = scrypt.hash(secret_key, params);
	console.log('Hash (sync): ' + hash);
} catch(e) {
	console.log(e);
	process.exit(1);
}

// hash verify (sync)
try {
	_.assign(scrypt.verify.config, options.verify_config);
	var hash_verify = scrypt.verify(hash, secret_key);
	console.log('Hash verify (sync): ' + hash_verify);
} catch(e) {
	console.log(e);
	process.exit(1);
}

// kdf (sync)
try {
	_.assign(scrypt.kdf.config, options.kdf_config);
	var hashed_key = scrypt.kdf(secret_key, options.kdf_params);
	console.log('KDF hash (sync): ' + hashed_key.hash);
	console.log('KDF salt (sync): ' + hashed_key.salt);
} catch(e) {
	console.log(e);
	process.exit(1);
}
