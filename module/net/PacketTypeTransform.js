const {
    Transform
} = require('stream');
const hexy = require('hexy').hexy;

const FieldType = {
    "CHAR": 0x00,
    "INT8": 0x01,
    "UINT8": 0x02,
    "INT16": 0x03,
    "UINT16": 0x04,
    "INT32": 0x05,
    "UINT32": 0x06,
    "INT64": 0x07,
    "UINT64": 0x08,
    "FLOAT": 0x09,
    "VEC3": 0x0A,
    "MATRIX": 0x0B,
    "PACKET": 0x0C,
    "MEMORY_BLOCK": 0x0D,
    "VEC3Extra": 0x0E,
    "WCHAR": 0x0F,
    "MAX": 0xFF,
};

module.exports.FieldType = FieldType;

const util = require('util');
const crypto = require('crypto');
const generateKey = util.promisify(crypto.randomBytes);
module.exports.generateKey = generateKey;

class Collection {
    constructor() {
        this.items = {};
    }

    add(typeID, name, handler, fields, sizes, names, flagSize) {
        // TODO: Checks on fields and sizes?

        // Attempt to auto set flag size.
        if (flagSize === undefined) {
            flagSize = Math.ceil(fields.length/8);

            // Note: A size of 3 is not supported so bump it up to 4 if so.
            if (flagSize === 3) {
                flagSize = 4;
            }
        }

        if (flagSize > 4) {
            throw new Error("Flag Size can't be greater than 4 error defining typeID: " + typeID);
        }

        this.items[typeID] = {
            name: name,
            handler: handler,
            fields: fields,
            sizes: sizes,
            names: names || [],
            flagSize: flagSize
        }
    }

    get(typeID) {
        return this.items[typeID];
    }
}

module.exports.Collection = Collection;

/**********************************
 * Reading functions.
 ***********************************/

const FieldTypeReadFunction = [];

FieldTypeReadFunction[FieldType.CHAR] = function ReadField_CHAR(chunk, position, size) {
    return [chunk.toString('utf8', position, position + size), size];
};

FieldTypeReadFunction[FieldType.INT8] = function ReadField_INT8(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type INT8 with size '+size+' is not yet implemented.');
    }
    return [chunk.readInt8(position), size];
};

FieldTypeReadFunction[FieldType.UINT8] = function ReadField_UINT8(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type UINT8 with size '+size+' is not yet implemented.');
    }
    return [chunk.readUInt8(position), size];
};

FieldTypeReadFunction[FieldType.INT16] = function ReadField_INT16(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type INT16 with size '+size+' is not yet implemented.');
    }
    return [chunk.readInt16(position), size * 2];
};

FieldTypeReadFunction[FieldType.UINT16] = function ReadField_UINT16(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type UINT16 with size '+size+' is not yet implemented.');
    }
    return [chunk.readUInt16(position), size * 2];
};

FieldTypeReadFunction[FieldType.INT32] = function ReadField_INT32(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type INT32 with size '+size+' is not yet implemented.');
    }
    return [chunk.readInt32(position), size * 4];
};

FieldTypeReadFunction[FieldType.UINT32] = function ReadField_UINT32(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type UINT32 with size '+size+' is not yet implemented.');
    }
    return [chunk.readUInt32(position), size * 4];
};

FieldTypeReadFunction[FieldType.INT64] = function ReadField_INT64(chunk, position, size) {
    throw new Error('Reading field type INT64 is not yet implemented.');
};

FieldTypeReadFunction[FieldType.UINT64] = function ReadField_UINT64(chunk, position, size) {
    throw new Error('Reading field type UINT64 is not yet implemented.');
};

FieldTypeReadFunction[FieldType.FLOAT] = function ReadField_FLOAT(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type FLOAT with size '+size+' is not yet implemented.');
    }
    return [chunk.readFloatLE(position), size * 4];
};

FieldTypeReadFunction[FieldType.VEC3] = function ReadField_VEC3(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type VEC3 with a size of '+size+' is not yet implemented.');
    }

    var vec3 = [chunk.readFloatLE(position),chunk.readFloatLE(position + 4), chunk.readFloatLE(position + 8)]
    return [vec3, 12 * size];
};

FieldTypeReadFunction[FieldType.MATRIX] = function ReadField_MATRIX(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type MATRIX with size '+size+' is not yet implemented.');
    }

    var matrix = [
        chunk.readFloatLE(position), chunk.readFloatLE(position + 4), chunk.readFloatLE(position + 8), chunk.readFloatLE(position + 12),
        chunk.readFloatLE(position + 16), chunk.readFloatLE(position + 20), chunk.readFloatLE(position + 24), chunk.readFloatLE(position + 28),
        chunk.readFloatLE(position + 32), chunk.readFloatLE(position + 36), chunk.readFloatLE(position + 40), chunk.readFloatLE(position + 44),
        chunk.readFloatLE(position + 48), chunk.readFloatLE(position + 52), chunk.readFloatLE(position + 56), chunk.readFloatLE(position + 60)
    ];

    return [matrix, 64 * size];
};

FieldTypeReadFunction[FieldType.PACKET] = function ReadField_PACKET(chunk, position, size) {
    throw new Error('Reading field type PACKET is not yet implemented.');
};

FieldTypeReadFunction[FieldType.MEMORY_BLOCK] = function ReadField_MEMORY_BLOCK(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type MEMORY_BLOCK with a size of '+size+' is not yet implemented.');
    }
    var length = chunk.readUInt16LE(position);
    position += 2;
    var data = chunk.slice(position, position + length);
    return [data, 2 + length];
};

FieldTypeReadFunction[FieldType.VEC3Extra] = function ReadField_VEC3Extra(chunk, position, size) {
    throw new Error('Reading field type VEC3Extra is not yet implemented.');
};

FieldTypeReadFunction[FieldType.WCHAR] = function ReadField_WCHAR(chunk, position, size) {
    // I did this already in another project. (CAPS) can probably re-use?
    throw new Error('Reading field type WCHAR is not yet implemented.');
};


/**********************************
 * Writing functions.
 ***********************************/

const FieldTypeWriteFunction = [];

FieldTypeWriteFunction[FieldType.CHAR] = function WriteField_CHAR(value, chunk, position, size) {
    chunk.write(value, position, value.length, 'utf8');
    return 1 * size;
};

FieldTypeWriteFunction[FieldType.INT8] = function WriteField_INT8(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing INT8 is not yet implemented with size > 1.');
    }
    chunk.writeInt8(value, position);
    return 1;
};

FieldTypeWriteFunction[FieldType.UINT8] = function WriteField_UINT8(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing UINT8 is not yet implemented with size > 1.');
    }
    chunk.writeUInt8(value, position);
    return 1;
};

FieldTypeWriteFunction[FieldType.INT16] = function WriteField_INT16(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing INT16 is not yet implemented with size > 1.');
    }
    chunk.writeInt16(value, position);
    return 2;
};

FieldTypeWriteFunction[FieldType.UINT16] = function WriteField_UINT16(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing UINT16 is not yet implemented with size > 1.');
    }
    chunk.writeUInt16(value, position);
    return 2;
};

FieldTypeWriteFunction[FieldType.INT32] = function WriteField_INT32(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing INT32 is not yet implemented with size > 1.');
    }
    chunk.writeInt32(value, position);
    return 4;
};

FieldTypeWriteFunction[FieldType.UINT32] = function WriteField_UINT32(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing UINT32 is not yet implemented with size > 1.');
    }
    chunk.writeUInt32(value, position);
    return 4;
};

FieldTypeWriteFunction[FieldType.INT64] = function WriteField_INT64(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing INT64 is not yet implemented with size > 1.');
    }
    throw new Error('Writing INT64 is not yet implemented.');
};

FieldTypeWriteFunction[FieldType.UINT64] = function WriteField_UINT64(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing UINT64 is not yet implemented with size > 1.');
    }
    throw new Error('Writing UINT64 is not yet implemented.');
};

FieldTypeWriteFunction[FieldType.FLOAT] = function WriteField_FLOAT(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing FLOAT is not yet implemented with size > 1.');
    }
    chunk.writeFloatLE(value, position);
    return 4;
};

FieldTypeWriteFunction[FieldType.VEC3] = function WriteField_VEC3(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing VEC3 is not yet implemented with size > 1.');
    }
    chunk.writeFloatLE(value, position);
    chunk.writeFloatLE(value, position + 4);
    chunk.writeFloatLE(value, position + 8);
    return 12;
};

FieldTypeWriteFunction[FieldType.MATRIX] = function WriteField_MATRIX(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing MATRIX is not yet implemented with size > 1.');
    }
    throw new Error('Writing MATRIX is not yet implemented.');
};

FieldTypeWriteFunction[FieldType.PACKET] = function WriteField_PACKET(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing PACKET is not yet implemented with size > 1.');
    }
    throw new Error('Writing PACKET is not yet implemented.');
};

FieldTypeWriteFunction[FieldType.MEMORY_BLOCK] = function WriteField_MEMORY_BLOCK(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing MEMORY_BLOCK is not yet implemented with size > 1.');
    }
    value.copy(chunk, position);
    return value.length;
};

FieldTypeWriteFunction[FieldType.VEC3Extra] = function WriteField_VEC3Extra(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing VEC3Extra is not yet implemented with size > 1.');
    }
    throw new Error('Writing VEC3Extra is not yet implemented.');
};

FieldTypeWriteFunction[FieldType.WCHAR] = function WriteField_WCHAR(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing WCHAR is not yet implemented with size > 1.');
    }
    throw new Error('Writing WCHAR is not yet implemented.');
};


/**
 * A stream transformer to take an incomming stream of TCP bytes and
 * turn it into workable buffers.
 * 
 * The structure is.
 * 
 * Each packet of data we are interested
 * 
 * @class Decoder
 * @extends {Transform}
 */
class Decoder extends Transform {
    constructor(options) {
        if (options === undefined) {
            options = {};
        }

        options.objectMode = true;
        super(options);

        this.collection = null;
        if (options.collection) {
            this.collection = options.collection;
        }

        this.options = options;
    }

    /**
     * Transform function collect chunks and output each complete buffer.
     * 
     * The smallest potential packet may be?
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
     * @memberof Decoder
     */
    _transform(chunk, enc, cb) {
        // It might be possible to have a 0 byte chunk?
        if (chunk.length === 0) {
            return cb(null, chunk);
        }

        if (chunk.length < 6) {
            return cb(new Error("Expecting more data in packet."));
        }

        // TODO: Remove debug.
        console.info(hexy(chunk));

        var output = {};

        var position = 0;

        // TODO: Do something like this, maybe it should be two code paths?
        // var [ packet, bytesRead ] = readPacket(chunk, { includeTimestamp: this.options.includeTimestamp });
        // position += bytesRead;

        output.packetTypeID = chunk.readUInt16LE(position);
        position += 2;

        output.sessionID = chunk.readUInt32LE(position);
        position += 4;

        var expectingLength = 6;
        if (this.options.includeTimestamp) {
            expectingLength += 4;
            if (chunk.length < 10) {
                return cb(new Error("Expecting more data in packet."));
            }

            // Can we convert timestamp into date object?
            output.timestamp = chunk.readUInt32LE(position);
            position += 4;
        }

        // Note: Not sure if this covers all circumstances.
        if (chunk.length < expectingLength) {
            return cb(new Error("Expecting more data in packet."));
        }

        // Could consider this an error.
        // But whilst in development we will just warn to console.
        if (this.collection === null) {
            console.warn('Collection not specified on PacketTypeTransform Decoder.');
            return cb();
        }

        // Store the buffer into the packet output for debug reasons.
        output.buffer = chunk.slice(3);

        // Packet Info to contain.
        // types
        // sizes
        // names (optional)
        // flagSize (can be 1, 2 or 4).

        // The flag bits will indicate which types are present in the packet.

        output.flags = [];

        // TODO: Take this whole section and make it a function so we can use it to read embedded packets.
        var packetInfo = this.collection.get(output.packetTypeID);

        // If we can not find the collection then.
        if (packetInfo === null) {
            // Note: In development mode it's going to be useful to output some info here.
            console.warn("Packet Type " + output.packetTypeID + " not found.", chunk);

            // TODO: Lets error?
            //return cb(new Error('Packet Type ' + output.packetTypeID + ' not found.'));

            // Whilst Developing, pass it on anyway as it could be handy to use the buffer to work out what the packet is...
            return cb(null, output);
        }

        if (packetInfo.flagSize === 1) {
            output.flagValue = chunk.readUInt8(position);
            position ++;
        } else if (packetInfo.flagSize === 2) {
            output.flagValue = chunk.readUInt16LE(position);
            position += 2;
        } else if (packetInfo.flagSize === 4) {
            output.flagValue = chunk.readUInt32LE(position);
            position += 4;
        }

        // TODO: Can probably move these checks into the collection add method?
        if (packetInfo.fields.length > 32) {
            return cb(new Error("Too many types present, must fit into 8, 16 or 32 bits."));
        }

        output.info = packetInfo;
        output.content = {};

        if (output.flagValue) {
            for (var i = 0; i < packetInfo.fields.length; i++) {

                // Bit Index & Mask
                // Note: Can be obtained by 1 << index
                // This presumably gives us a max of 32 fields in a packet?
                // But the blocks can be embedded inside each other actually.
                var mask = 1 << i;
                output.flags[i] = (output.flagValue & mask)

                if (output.flags[i]) {
                    try {
                        // TODO: Handle array / var length?
                        // For each type present, read it from the packet.
                        var fieldType = packetInfo.fields[i];
                        var readFieldFunction = FieldTypeReadFunction[fieldType];
                        if (readFieldFunction === undefined) {
                            console.info("Field Type " + fieldType + " read is not implemented.");
                            return cb(new Error("Reading field type " + fieldType + " is not implemented."));
                        }
                        
                        var [value, bytesRead] = readFieldFunction(chunk, position, packetInfo.sizes[i]);

                        // Set field name in content if present.
                        var fieldName = packetInfo.names[i];
                        if (fieldName !== undefined) {
                            output.content[fieldName] = value;
                        } else {
                            // Just set it by index since we don't know the field name.
                            // We hope to recover all field names if possible.
                            output.content[i] = value;
                        }

                        position += bytesRead;
                    } catch (e) {
                        return cb(e);
                    }
                }
            }
        }

        cb(null, output);
    }
}

module.exports.Decoder = Decoder;

class PacketWriter {
    constructor(options) {
        // Note: Max size of buffer appears to be 2147483647.
        if (options.writeBufferLength === undefined) {
            options.writeBufferLength = 1024;
        }

        // Preallocate a buffer to store the WIP packet as it is constructed.
        this.writeBuffer = Buffer.allocUnsafe(options.writeBufferLength);

        this.collection = null;
        if (options.collection) {
            this.collection = options.collection;
        }

        this.startByte = 0xD6;
        this.endByte = 0x6B;

        this.sessionID = 0;

        this.options = options;
    }

    /* Returns a new buffer or throws an exception. */
    createPacket(packetTypeID, object) {
        var packetInfo = this.collection.get(packetTypeID);

        // If we can not find the collection then.
        if (packetInfo === null) {
            throw new Error('Packet info not found for PacketTypeID: '+packetTypeID);
        }

        var position = 0;

        // Increment space for guard byte.
        //this.writeBuffer.writeUInt8(this.startByte, position);
        position += 1;

        // Increment space for packet size.
        position += 2;

        // Write packet type id.
        this.writeBuffer.writeUInt8(packetTypeID, position);
        position += 1;

        // Increment space for unknown byte.
        position += 1;

        // Write session id
        //this.writeBuffer.writeUInt32LE(100, position);
        //position += 4;
        // Increment space for session id.
        position += 4;

        if (this.options.includeTimestamp) {
            this.writeBuffer.writeUInt32LE((new Date()).getTime(), position);
            position += 4;
        }

        // Store the flag bytes position for writing later.
        var flagPosition = position;

        // Move position by the flag size.
        position += packetInfo.flagSize;

        var flagValue = 0;
        
        for (var i = 0; i < packetInfo.fields.length; i++) {

            // Bit Index & Mask
            // Note: Can be obtained by 1 << index
            // This presumably gives us a max of 32 fields in a packet?
            // But the blocks can be embedded inside each other actually.
            var mask = 1 << i;

            // TODO: Consider if we want encode null as 0?

            // Get the value for the field, by field name if set or index if field name not set.
            var fieldName = packetInfo.names[i];
            var value = null;
            if (fieldName !== undefined && object[fieldName] !== undefined) {
                value = object[fieldName];
                flagValue |= mask;
            } else if (object[i] !== undefined) {
                flagValue |= mask;
                value = object[i];
            } else {
                // Nothing to write for this field.
                continue;
            }

            var fieldType = packetInfo.fields[i];
            var writeFieldFunction = FieldTypeWriteFunction[fieldType];
            if (writeFieldFunction === undefined) {
                console.info("Field Type " + fieldType + " write is not implemented.");
                throw new Error("Writing field type " + fieldType + " is not implemented.");
            }

            // Write the field to the buffer and increment position accordingly.
            position += writeFieldFunction(value, this.writeBuffer, position, packetInfo.sizes[i]);
        }


        // Write the flag byte(s).
        if (packetInfo.flagSize === 1) {
            this.writeBuffer.writeUInt8(flagValue, flagPosition);            
        } else if (packetInfo.flagSize === 2) {
            this.writeBuffer.writeUInt16LE(flagValue, flagPosition);
        } else if (packetInfo.flagSize === 4) {
            this.writeBuffer.writeUInt32LE(flagValue, flagPosition);
        }

        // Write total length, putting position as the value is intentional.
        this.writeBuffer.writeUInt16LE(position, 1);

        // Increment space for guard byte.
        //this.writeBuffer.writeUInt8(this.endByte, position);
        position += 1;

        // Return a new buffer of our packet.
        var output = Buffer.from(this.writeBuffer.slice(0, position));

        return output;
    }

    encryptPacketBuffer(socket, buffer, options) {
        // Set the guard bytes correctly.
        // Set any packet increment or session id correctly.
        // Encrypt the buffer and copy contents from the cipher output.

        
        buffer.writeUInt8(0xD6, 0);
        
        buffer.writeUInt32LE(0, 5);

        var position = 9;
        var size = buffer.length - 1 - position;


        var cipher = crypto.createCipher('blowfish', socket.writer.getKey());
        var data = cipher.update(buffer.slice(position));
        data.copy(buffer, position);
        position += data.length;


        // const crypto = require('crypto');
        // var cipher = crypto.createCipher('blowfish', new Buffer(32));
        // var data = Buffer.concat([cipher.update(new Buffer(7)),cipher.update(new Buffer(1))]);
        // //Buffer.concat(cipher.update(data),cipher.final())
        // //var data = cipher.update(new Buffer(8));
        // console.log("Length: "+data.length+"\n"+hexy(data));
        

        // Handle any remaining length with padding to make up a block size of 8.
        var remaining = size % 8;
        if (remaining !== 0) {
            data = cipher.update(Buffer.allocSafe(8 - remaining));
            data.copy(buffer, position, 0, remaining);
            position += remaining;
        }

        buffer.writeUInt8(0x6B, position);
    }
}

module.exports.PacketWriter = PacketWriter;

/**
 * A stream transformer to take an incomming stream of TCP bytes and
 * turn it into workable buffers.
 * 
 * The structure is.
 * 
 * Each packet of data we are interested
 * 
 * @class Encoder
 * @extends {Transform}
 */
class Encoder extends Transform {
    constructor(options) {
        if (options === undefined) {
            options = {};
        }

        super(options);

        this.packetWriter = new PacketWriter(options);



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
     * @memberof Encoder
     */
    _transform(chunk, enc, cb) {
        // TODO: Merge the two transform streams (PacketTypeTransform and FrameStreamTransform) into 1 as it would make more sense.
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

module.exports.Encoder = Encoder;