/* jslint node: true */
'use strict';

var CryptoWrapper = require('../lib/crypto-wrapper');
var crypto = new CryptoWrapper();

var data = 'MyPassword123';
var hash = crypto.Hash(data);

console.log('=== BEGIN SECRET ===');
console.log(data);
console.log('=== HASH ===');
console.log(hash);
console.log('=== END DATA ===');

console.log('Valid hash: ' + crypto.VerifyHash(data, hash));
