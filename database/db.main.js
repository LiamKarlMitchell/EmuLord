const promise = require('bluebird'); // or any other Promise/A+ compatible library;
var Config = require('../config/database')

const initOptions = {
    promiseLib: promise // overriding the default (ES6 Promise);
}

// const monitor = require('pg-monitor')

// if (Config.game.monitor) {
//     try {
//         monitor.attach(initOptions) // attach to all events at once
//     } catch (e) {
//         // We don't care, this monitor is just for debug purposes.
//     }
// }

const pgp = require('pg-promise')(initOptions)
// See also: http://vitaly-t.github.io/pg-promise/module-pg-promise.html

const db = pgp(Config.main) // database instance;

// Note: Conversions such as these may have loss of precision or errors.
// Convert bigserial + bigint (both with typeId = 20) to integer:
pgp.pg.types.setTypeParser(20, parseInt) // int8
pgp.pg.types.setTypeParser(21, parseInt) // int2
pgp.pg.types.setTypeParser(23, parseInt) // int4
pgp.pg.types.setTypeParser(700, parseFloat) // float4
pgp.pg.types.setTypeParser(701, parseFloat) // float8
pgp.pg.types.setTypeParser(1700, parseFloat) // numeric

// Many specific types will become broken due to their specific presentation required by PostgreSQL. For example, floating-point values, with their special support for such values as NaN, +Infinity and -Infinity.
// pg has support for these but we would need to convert to them from js.
// '+infinity'
// '-infinity';
// NaN
// We could use isFinite before storing the values.

module.exports = db
