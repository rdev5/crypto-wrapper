/* jslint node: true */
'use strict';
var crypto = require('crypto');
var uuid = require('node-uuid');

function Deprecated() {}

// @return string self.HashCrypto(data, seed_length);
Deprecated.prototype.HashCrypto = function(data, iterations) {
	var self = this;

   for (var i = 1; i <= iterations; i++) {
      var hasher = crypto.createHash('sha512');
      hasher.update(data);
      data = hasher.digest('hex');
   }

   return data;
};

// @return bool VerifyHashCrypto(data, hash)
Deprecated.prototype.VerifyHashCrypto = function(data, hash) {
	var self = this;

   return self.HashCrypto(data) === hash;
};

// @return string self.GenerateSalt(salt_rounds, seed_length)
Deprecated.prototype.GenerateSalt = function(salt_rounds, seed_length) {
	var self = this;

   // var salt = uuid.v4();
   // salt = salt.replace(/\-/g, self.RandomString(1));
};

// @return string self.RandomString(len, char_selection)
Deprecated.prototype.RandomString = function(len, possible) {
	var self = this;

   var text = "";

   if (!possible) {
      possible = "$#*ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   }

   for( var i=0; i < len; i++ )
   text += possible.charAt(Math.floor(Math.random() * possible.length));

   return text;
};

// @return string self.GenerateKey()
Deprecated.prototype.GenerateKey = function() {
	var self = this;

   return (uuid.v4()).replace(/\-/g, self.RandomString(1));
};

// @return string self.ShuffleSttring(str)
Deprecated.prototype.ShuffleString = function(value) {
	var self = this;

   var a = value.split(""),
      n = a.length;

   for(var i = n - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var tmp = a[i];
      a[i] = a[j];
      a[j] = tmp;
   }

   return a.join("");
};

// @return array buffer self.Blocks(buffer, size)
Deprecated.prototype.Blocks = function(buffer, size) {
	var self = this;

   var len = buffer.length;
   var rounds = Math.ceil(len / size);

   var blocks = [];
   for (var i = 1; i <= rounds; i++) {
      var block = new Buffer(size);
      var start = (i - 1) * size;

      buffer.copy(block, 0, start, start+size);
      blocks.push(block);
   }

   return blocks;
};

module.exports = Deprecated;