/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper')
var crypto = new CryptoWrapper();

var data = 'Hi John!\n\nIt was nice meeting up with you at CryptoCon this past weekend. Here is my public key:\nABCDEF123\n\nBob'

console.log('=== BEGIN MESSAGE ===')
console.log(data);
console.log('=== SIGNATURE ===');
console.log(crypto.Sign(data));
console.log('=== END MESSAGE ===');
