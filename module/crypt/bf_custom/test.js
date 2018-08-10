// this is how we will require our module
const m = require('./')
var hexy = require('hexy').hexy;

const bf = new m.BlowFish()
console.log(bf)

console.log(hexy(Buffer.from('test')));

var key = Buffer.from('11111111111111111111111111111111');
bf.setKey(key);

var buffer = Buffer.from("Mary had a little lamb.");

console.log('Before');
console.log(hexy(buffer));


bf.encrypt(buffer);

console.log('Encrypted');
console.log(hexy(buffer));

bf.decrypt(buffer);

console.log('Decrypted');
console.log(hexy(buffer));

console.log(buffer.toString('utf8'));



const blowfish = new m.BlowFish();
blowfish.setKey(Buffer.from("12345678123456781234567812345678"));

var data = Buffer.from("7864ce3300705d687e298ed2294264daf25eb73b87283d8593d60df9c2c6f898","hex");

console.log("Data Encrypted:\n"+hexy(data));

blowfish.decrypt(data);

var decryptedData = Buffer.from("C1071F5806C5DA9C616D347E6041A1958F63FC71E7D65624DCF17CEF027DA977","hex");

console.log("Data Decrypted:\n"+hexy(data));
console.log("Expected Result:\n"+hexy(decryptedData));

if (Buffer.compare(data, decryptedData) !== 0) {
	console.error("Decrypted data test failed.");
} else {
	console.log("Decrypted data test passed.");
}


console.log('DONE');

