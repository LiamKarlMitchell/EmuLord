var bf_custom;

// Note: Uncomment if you want release or debug build.
//bf_custom = require('./build/Release/bf_custom.node');
bf_custom = require('./build/Debug/bf_custom.node');

module.exports = bf_custom;