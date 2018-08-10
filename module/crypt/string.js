const crypto = require('crypto');

function decipherText(input, key) {
    var decipher = crypto.createDecipher('rc4', key);
    return decipher.update(input, 'binary', 'utf8') + decipher.final('utf8');
}

function cipherText(input, key) {
    var cipher = crypto.createCipher('rc4', key);
    return cipher.update(input, 'binary', 'utf8') + cipher.final('utf8');
}

module.exports.decipherText = decipherText;
module.exports.cipherText = cipherText;