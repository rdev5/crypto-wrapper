/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

crypto.options.private_key_file = './examples/keyfiles/sample-privkey.pem';
crypto.options.public_key_file = './examples/keyfiles/sample-key.pub';

var data = 'Hi John!\n\nIt was nice meeting up with you at CryptoCon this past weekend. Here is my public key:\nABCDEF123\n\nBob';
var data_sig = crypto.Sign(data);

console.log('=== BEGIN MESSAGE ===');
console.log(data);
console.log('=== SIGNATURE ===');
console.log(data_sig);
console.log('=== END MESSAGE ===');

console.log('Valid signature: ' + crypto.VerifySignature(data, data_sig));
