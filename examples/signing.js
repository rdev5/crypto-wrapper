/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

var data = 'Hi John!\n\nIt was nice meeting up with you at CryptoCon this past weekend. Here is my public key:\nABCDEF123\n\nBob';
var data_sig = crypto.Sign(data);

console.log('=== BEGIN MESSAGE ===');
console.log(data);
console.log('=== SIGNATURE ===');
console.log(data_sig);
console.log('=== END MESSAGE ===');

console.log('Valid signature: ' + crypto.Verify(data, data_sig));
