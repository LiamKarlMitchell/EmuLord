const { Transform } = require('stream');

/**
 * A stream transformer to take an incomming stream of TCP bytes and
 * turn it into workable buffers.
 * 
 * The structure is.
 * 
 * Each packet of data we are interested
 * 
 * @class Deframer
 * @extends {Transform}
 */
class Deframer extends Transform {
    constructor(options) {
        if (options === undefined) {
            options = {};
        }

        super(options);

        this.options = options;
  }

  /**
   * Transform function collect chunks and output each complete buffer.
   * 
   * The smallest potential packet would be
   * D6 04 00 6B
   * 
   * Guard bytes are D6 and 6B around the data.
   * A unsigned short is then the length of the internal data + length of guard bytes and length.
   * After the short is a block of bytes length - 4 but if the length is a 4 then obviously there is no data.
   * 
   * @param {any} chunk 
   * @param {any} enc 
   * @param {any} cb 
   * @returns 
   * @memberof Deframer
   */
  _transform(chunk, enc, cb) {
      // It might be possible to have a 0 byte chunk?
      if (chunk.length === 0) {
          return cb(null, chunk);
      }

      var position = 0;

      // Restore buffered content if any.
      if (this.buffer) {
        chunk = Buffer.concat([this.buffer, chunk]);
        this.buffer = null;
      }

      var totalLength = chunk.length;

      while (position < totalLength) {
        // Keep to max size limits.
        if (this.options.maxSize > 0 && chunk.length > this.options.maxSize) {
            return cb(new Error('Message larger than max size allowed.'));
        }

        // We have a minimum size requirement of 4 bytes. (Could be 12 or 16 presumably if we didn't have empty packet and included some other fields...)
        if (chunk.length < 4) {
            // TODO: Retain missed counter?

            // Wait for more data.
            this.buffer = chunk;
            return cb();
        }

        // Get the starting byte.
        var startByte = chunk.readUInt8(position);
        position ++;

        if (startByte !== 0xD6 && startByte != 0xA1 && startByte != 0xB1) {
            return cb(new Error('Unrecognized start byte of packet frame.'));
        }

        // Read length.
        var length = chunk.readUInt16LE(position);
        position += 2;

        if (totalLength < length) {
            // TODO: Retain missed counter?

            // Wait for more data.
            this.buffer = chunk;
            return cb();
        }

        var lastByte = chunk.readUInt8(position + length - 4);
        
        // If starting with D6 ensure the last byte is 6B
        // If starting with A1 ensure the last byte is AF
        // If starting with B1 ensure the last byte is BF
        if (startByte == 0xD6 && lastByte != 0x6B) {
            return cb(new Error('Packet frame not ending in correct byte.'));
        }
        else if (startByte == 0xA1 && lastByte != 0xAF) {
            return cb(new Error('Packet frame not ending in correct byte.'));
        }
        else if (startByte == 0xB1 && lastByte != 0xBF) {
            return cb(new Error('Packet frame not ending in correct byte.'));
        }

        // Slice the data of interest, we don't care about the tail byte.
        var data = chunk.slice(position, position + length - 4);

        // Push it along.
        this.push(data);
        position += length - 3;
      }

	  cb();
  }
}

module.exports.Deframer = Deframer;

/**
 * A stream transformer to take an incomming stream of TCP bytes and
 * turn it into workable buffers.
 * 
 * The structure is.
 * 
 * Each packet of data we are interested
 * 
 * @class Framer
 * @extends {Transform}
 */
class Framer extends Transform {
    constructor(options) {
        if (options === undefined) {
            options = {};
        }

        super(options);

        this.startByte = 0xD6;
        this.endByte = 0x6B;

        this.options = options;
  }

  /**
   * Transform function output a framed version of a complete packet buffer.
   * 
   * The smallest potential packet would be from a length of 0.
   * D6 04 00 6B
   * 
   * Guard bytes are D6 and 6B around the data.
   * A unsigned short is then the length of the internal data + length of guard bytes and length.
   * After the short is a block of bytes length - 4 but if the length is a 4 then obviously there is no data.
   * 
   * @param {any} chunk 
   * @param {any} enc 
   * @param {any} cb 
   * @returns 
   * @memberof Framer
   */
  _transform(chunk, enc, cb) {
    // Make a buffer to pass on.
    var output = new Buffer(chunk.length + 4);

    // Write start byte.
    output.writeUInt8(this.startByte, 0);

    // Write length.
    output.writeUInt16LE(chunk.length + 4, 1);

    // Write chunk.
    chunk.copy(output, 3, 0, chunk.length);

    // Write end byte.
    output.writeUInt8(this.endByte, 3 + chunk.length);

    // Pass it on.
    cb(null, output);

    // TODO: Allocating buffers is going to be expensive? Maybe we should pre-allocate large buffers and re-use?
  }
}

module.exports.Framer = Framer;