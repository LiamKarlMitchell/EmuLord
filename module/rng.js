var Random = require('random-js');

// Create a Mersenne Twister-19937.
var mt = Random.engines.mt19937();

if (process.env.rng_seed) {
    // That is seeded by a user supplied input.
    mt.seed(value);
} else {
    // That is auto-seeded based on time and other random values.
    mt.autoSeed();
}

function MyRandom() {
  return Random.call(this, mt);
}

MyRandom.prototype = Object.create(Random.prototype);
MyRandom.prototype.constructor = MyRandom;

module.exports = new MyRandom();