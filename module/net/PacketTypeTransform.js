const { Transform } = require('stream');
const util = require('util');
const crypto = require('crypto');
const hexy = require('hexy').hexy;
const { BlowFish }  = require('../crypt/bf_custom');

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

// A helper method to generate an encryption key.
const generateKey = util.promisify(crypto.randomBytes.bind(crypto, 32));
module.exports.generateKey = generateKey;


function unhandledStructure(socket, packet) {
    // TODO: Consider if we want to error here or just continue on?
    console.warn("Unhandled packet received.");
    throw new Error("Unhandled packet received.");
}

function processOperations(socket, packet) {
    if (packet.info.operations === undefined) {
        throw new error("Structure " + packet.info.name + "operations not set.");
    }

    var operation = packet.info.operations[packet.content.operation];
    
    if (operation === undefined) {
        operation = nooperation;
    }

    operation(socket, packet);
}

function nooperation(socket, packet) {
    console.warn("Unhandled operation "+packet.content.operation+" for packet type: "+packet.packetTypeID+".", packet.content, "Data: \n"+hexy(packet.buffer));
    throw new Error("Unhandled operation "+packet.content.operation+" for packet "+packet.packetTypeID+".");
}

class Structure {
    constructor(name) {
        this.name = name;
        this.handler = unhandledStructure;

        this.flagSize = 1;

        this.fields = [];
        this.sizes = [];
        this.names = [];

        this.structures = [];
    }

    structure(structure, size = 1, name = undefined){
        if (name === undefined) {
            if (structure && structure.name === undefined) {
                name = this.fields.length;
                structure.name = name;
            } else {
                if (structure && structure.name) {
                    name = structure.name;
                }
            }
        }

        // TODO: Consider, rather than mapping function to read/write by fieldTypeID we could just map it here?
        this.fields.push(FieldType.PACKET);
        this.sizes.push(size);
        this.names.push(name);

        // Undefined being allowed is intentional here, if we run into an undefined structure during encode or decode then we will error.
        this.structures.push(structure);

        if (structure !== undefined) {
            var flagSize = Math.ceil(structure.fields.length / 8);

            // Note: A size of 3 is not supported so bump it up to 4 if so.
            if (flagSize === 3) {
                flagSize = 4;
            }

            if (flagSize > 4) {
                throw new Error("Flag Size can't be greater than 4 error defining structure "+name);
            }

            structure.flagSize = flagSize;

            delete structure['handler'];
        }

        return this;
    }

    /**
     * A helper for uint8(1, 'operation') with a function(s) to call to handle it.
     * Add as many times as needed.
     * @memberof Structure
     */
    operation(id, func) {
        if (this.operations === undefined) {
            this.operations = {};

            this.uint8(1, 'operation');

            this.handler = processOperations;
        }

        if (func === undefined) {
            func = nooperation;
        }

        // Ensure the operation id is a number and that its not undefined.
        if (id !== undefined && !isNaN(id)) {
            this.operations[id] = func;
        }

        return this;
    }

    // TODO: Type check.
    char(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.CHAR);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    int8(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.INT8);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    uint8(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.UINT8);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    int16(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.INT16);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    uint16(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.UINT16);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    int32(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.INT32);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    uint32(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.UINT32);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    int64(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.INT64);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    uint64(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.UINT64);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    float(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.FLOAT);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    vec3(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.VEC3);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    matrix(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.MATRIX);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    memory_block(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.MEMORY_BLOCK);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    /**
     * An alias around memory_block.
     * 
     * @param {number} [size=1] 
     * @param {any} [name=undefined] 
     * @memberof Structure
     */
    buffer(size = 1, name = undefined) {
        this.memory_block(size, name);
    }

    vec3extra(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.VEC3EXTRA);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }

    wchar(size = 1, name = undefined) {
        if (name === undefined) {
            name = this.fields.length;
        }

        this.fields.push(FieldType.WCHAR);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }
}

Object.keys(FieldType).forEach(function(FieldTypeID){
    // Skip packet we will handle it custom.
    if (FieldTypeID === 'PACKET') {
        return;
    }
    Structure.prototype[FieldTypeID] = function(size = 1, name = undefined){
        if (name === undefined) {
            name = this.fields.length;
        }

        // TODO: Consider, rather than mapping function to read/write by fieldTypeID we could just map it here?
        this.fields.push(fieldTypeID);
        this.sizes.push(size);
        this.names.push(name);
        this.structures.push(undefined);

        return this;
    }
});

module.exports.Structure = Structure;

class Collection {
    constructor() {
        this.items = {};
    }

    packet(typeId, structure) {
        var flagSize = Math.ceil(structure.fields.length / 8);

        // Note: A size of 3 is not supported so bump it up to 4 if so.
        if (flagSize === 3) {
            flagSize = 4;
        }

        if (flagSize > 4) {
            throw new Error("Flag Size can't be greater than 4 error defining typeID: " + typeId);
        }

        structure.flagSize = flagSize;

        this.items[typeId] = structure;
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
    // We will read this backwards because that is how it is stored, size is last after fixed bytes of size.
    //var length = chunk.readUInt8(position + size);
    var string = chunk.toString('latin1', position, position + size);
    position += size; // + 1;
    return [string, size]; // +1
};

FieldTypeReadFunction[FieldType.INT8] = function ReadField_INT8(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type INT8 with size ' + size + ' is not yet implemented.');
    }
    return [chunk.readInt8(position), size];
};

FieldTypeReadFunction[FieldType.UINT8] = function ReadField_UINT8(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type UINT8 with size ' + size + ' is not yet implemented.');
    }
    return [chunk.readUInt8(position), size];
};

FieldTypeReadFunction[FieldType.INT16] = function ReadField_INT16(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type INT16 with size ' + size + ' is not yet implemented.');
    }
    return [chunk.readInt16LE(position), size * 2];
};

FieldTypeReadFunction[FieldType.UINT16] = function ReadField_UINT16(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type UINT16 with size ' + size + ' is not yet implemented.');
    }
    return [chunk.readUInt16LE(position), size * 2];
};

FieldTypeReadFunction[FieldType.INT32] = function ReadField_INT32(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type INT32 with size ' + size + ' is not yet implemented.');
    }
    return [chunk.readInt32LE(position), size * 4];
};

FieldTypeReadFunction[FieldType.UINT32] = function ReadField_UINT32(chunk, position, size) {
    // TODO: Larger than 1 size.
    if (size > 1) {
        throw new Error('Reading field type UINT32 with size ' + size + ' is not yet implemented.');
    }
    return [chunk.readUInt32LE(position), size * 4];
};

FieldTypeReadFunction[FieldType.INT64] = function ReadField_INT64(chunk, position, size) {
    throw new Error('Reading field type INT64 is not yet implemented.');
};

FieldTypeReadFunction[FieldType.UINT64] = function ReadField_UINT64(chunk, position, size) {
    throw new Error('Reading field type UINT64 is not yet implemented.');
};

FieldTypeReadFunction[FieldType.FLOAT] = function ReadField_FLOAT(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type FLOAT with size ' + size + ' is not yet implemented.');
    }
    return [chunk.readFloatLE(position), size * 4];
};

FieldTypeReadFunction[FieldType.VEC3] = function ReadField_VEC3(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type VEC3 with a size of ' + size + ' is not yet implemented.');
    }

    var vec3 = [chunk.readFloatLE(position), chunk.readFloatLE(position + 4), chunk.readFloatLE(position + 8)]
    return [vec3, 12 * size];
};

FieldTypeReadFunction[FieldType.MATRIX] = function ReadField_MATRIX(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type MATRIX with size ' + size + ' is not yet implemented.');
    }

    var matrix = [
        chunk.readFloatLE(position), chunk.readFloatLE(position + 4), chunk.readFloatLE(position + 8), chunk.readFloatLE(position + 12),
        chunk.readFloatLE(position + 16), chunk.readFloatLE(position + 20), chunk.readFloatLE(position + 24), chunk.readFloatLE(position + 28),
        chunk.readFloatLE(position + 32), chunk.readFloatLE(position + 36), chunk.readFloatLE(position + 40), chunk.readFloatLE(position + 44),
        chunk.readFloatLE(position + 48), chunk.readFloatLE(position + 52), chunk.readFloatLE(position + 56), chunk.readFloatLE(position + 60)
    ];

    return [matrix, 64 * size];
};

FieldTypeReadFunction[FieldType.PACKET] = function ReadField_PACKET(structure, chunk, position, size) {

    var startPosition = position;
    var hexy = require('hexy').hexy;
    //console.log("Position: "+position+" Data:\n"+hexy(chunk));

    var structureLength = chunk.readUInt16LE(position);
    position += 2;

    if (chunk.length - position < structureLength) {
        throw new Error('Not enough bytes to read packet.');
    }

    // Read structure flag bytes
    // Need to know what structure this actually is.
    
    // TODO: Consider if we can split this out into a function to be used for both packet and structures?
    var output = {
        flagValue: 0,
        content: {},
        flags: []
    };

    // Keeping variable names similar here to the other code.
    var packetInfo = structure;
    var data = chunk;
    var dataPosition = position;

    // Read the correct length of bytes for flag size.
    if (packetInfo.flagSize === 1) {
        output.flagValue = data.readUInt8(dataPosition);
        dataPosition++;
    } else if (packetInfo.flagSize === 2) {
        output.flagValue = data.readUInt16LE(dataPosition);
        dataPosition += 2;
    } else if (packetInfo.flagSize === 4) {
        output.flagValue = data.readUInt32LE(dataPosition);
        dataPosition += 4;
    }

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

                    if (fieldType === FieldType.PACKET) {
                        var [value, bytesRead] = readFieldFunction(packetInfo.structures[i], data, dataPosition, packetInfo.sizes[i]);
                    } else {
                        var [value, bytesRead] = readFieldFunction(data, dataPosition, packetInfo.sizes[i]);
                    }
                    

                    // Set field name in content if present.
                    var fieldName = packetInfo.names[i];
                    if (fieldName !== undefined) {
                        output.content[fieldName] = value;
                        console.log("Field: " + i + " " + fieldName + " = " + value);
                    } else {
                        // Just set it by index since we don't know the field name.
                        // We hope to recover all field names if possible.
                        output.content[i] = value;
                        console.log("Field: " + i + " = " + value);
                    }

                    dataPosition += bytesRead;
                } catch (e) {
                    return cb(e);
                }
            }
        }
    }

    // Last byte here should be a 6B
    // Followed by any 00 NULL byte padding.
    if (data.readUInt8(dataPosition) != 0x6B) {
        throw new Error("Not ending with correct byte.");
    }
    dataPosition ++;

    var leftOver = data.length - dataPosition;

    // TODO: Handle the padding? on end of packet type, as if we get structures or structures with more data after them this will cause problem.
    // Unless its always 4?
    if (leftOver != 4) {
        console.warn("Data left over after processing an embeeded structure is not 4 we need a propper way to handle padding!.");
    }
    //dataPosition += 4;

    // We are not interested in the rest of the data from the output just the content.
    return [output.content, dataPosition - startPosition];
};

FieldTypeReadFunction[FieldType.MEMORY_BLOCK] = function ReadField_MEMORY_BLOCK(chunk, position, size) {
    if (size > 1) {
        throw new Error('Reading field type MEMORY_BLOCK with a size of ' + size + ' is not yet implemented.');
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
    chunk.write(value.padEnd(size, "\0"), position, size, 'latin1');
    position += size;
    //chunk.writeInt8(value.length, position);
    //position ++;
    return size; // + 1
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
    chunk.writeInt16LE(value, position);
    return 2;
};

FieldTypeWriteFunction[FieldType.UINT16] = function WriteField_UINT16(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing UINT16 is not yet implemented with size > 1.');
    }
    chunk.writeUInt16LE(value, position);
    return 2;
};

FieldTypeWriteFunction[FieldType.INT32] = function WriteField_INT32(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing INT32 is not yet implemented with size > 1.');
    }
    chunk.writeInt32LE(value, position);
    return 4;
};

FieldTypeWriteFunction[FieldType.UINT32] = function WriteField_UINT32(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing UINT32 is not yet implemented with size > 1.');
    }
    chunk.writeUInt32LE(value, position);
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

FieldTypeWriteFunction[FieldType.PACKET] = function WriteField_PACKET(structure, object, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing PACKET is not yet implemented with size > 1.');
    }

    // TODO: Consider grouping the packet writing functionality for embedded structures into it's own function so we can reuse it in both places.

    // Keeping variable names the same here.
    var packetInfo = structure;

    // Store the flag bytes position for writing later.
    var beginPosition = position;

    // Increment position to leave room for the structure length short.
    position += 2;

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
        if (fieldType === FieldType.PACKET) {
            position += writeFieldFunction(packetInfo.structures[i], value, chunk, position, packetInfo.sizes[i]);
        } else {
            position += writeFieldFunction(value, chunk, position, packetInfo.sizes[i]);
        }
    }

    // Write the flag byte(s).
    if (packetInfo.flagSize === 1) {
        chunk.writeUInt8(flagValue, flagPosition);
    } else if (packetInfo.flagSize === 2) {
        chunk.writeUInt16LE(flagValue, flagPosition);
    } else if (packetInfo.flagSize === 4) {
        chunk.writeUInt32LE(flagValue, flagPosition);
    }

    var length = position - startPosition;

    // Write total length, putting start position as the value is intentional.
    chunk.writeUInt16LE(startPosition, length);

    // Return the length of data we have written.
    return length;
};

FieldTypeWriteFunction[FieldType.MEMORY_BLOCK] = function WriteField_MEMORY_BLOCK(value, chunk, position, size) {
    if (size > 1) {
        throw new Error('Writing MEMORY_BLOCK is not yet implemented with size > 1.');
    }
    // Write the length of the block.
    chunk.writeUInt16LE(value.length, position);
    position += 2;

    // Copy the block in.
    value.copy(chunk, position);
    return 2 + value.length;
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

        // Older client did not do this.
        if (options.useTimestamp === undefined) {
            options.useTimestamp = true;
        }

        this.key = null;
        this.blowfish = new BlowFish();

        // A temporary buffer to hold content between receives when we have only partial packet.
        this.buffer = null;

        this.sequenceCount = 0;

        this.options = options;
    }

    setKey(key) {
        this.key = key;

        if (this.key !== null) {
            this.blowfish.setKey(key);
        }
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

        var position = 0;

        // Restore buffered content if any.
        if (this.buffer !== null) {
            chunk = Buffer.concat([this.buffer, chunk]);
            this.buffer = null;
        }

        var totalLength = chunk.length;

        while (position < totalLength) {
            // Keep to max size limits.
            if (this.options.maxSize > 0 && chunk.length > this.options.maxSize) {
                return cb(new Error('Message larger than max size allowed.'));
            }

            // TODO: Remove this its just for debugging purposes atm as the Packet Sender loves to Append \r by default its checked when sending packets.
            if (chunk.readUInt8(position) === 0x0D) {
                continue;
            }

            // We have a minimum size requirement of 4 bytes. (Could be 12 or 15 presumably if we didn't have empty packet and included some other fields...)
            if (chunk.length < 15) {
                // TODO: Retain missed counter?

                // Wait for more data.
                this.buffer = chunk;
                return cb();
            }

            // Get the starting byte.
            var startByte = chunk.readUInt8(position);
            position++;

            // Check the start byte is correct.
            if (startByte !== 0xD6 && startByte !== 0xA1 && startByte !== 0xB1) {
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

            // We are at position 3 so we can get the last byte by position + length - 4.
            var lastByte = chunk.readUInt8(position + length - 4);

            // If starting with D6 ensure the last byte is 6B
            // If starting with A1 ensure the last byte is AF (Server sends this as the guard byte when encrypted)
            // If starting with B1 ensure the last byte is BF (Client sends this as the guard byte when encrypted)
            if (startByte === 0xD6 && lastByte !== 0x6B) {
                return cb(new Error('Packet frame not ending in correct byte.'));
            }
            else if (startByte === 0xB1 && lastByte !== 0xBF) {
                return cb(new Error('Packet frame not ending in correct byte.'));
            }

            // Slice the data of interest, we don't care about the tail byte.
            var data = chunk.slice(position, position + length - 4);
            
            console.log("Received: ",hexy(data));

            // Increment sequence counter.
            this.sequenceCount ++;

            // Parse the packet.
            if (data.length < 6) {
                return cb(new Error("Expecting more data in packet."));
            }

            // TODO: Remove this debug message.
            //console.info(hexy(data));

            var output = {};

            // Parse over the data for each individual packet.
            var dataPosition = 0;

            // TODO: Check sequence id for replay attack?

            // Handle Decryption if the key is set. 
            // Note: If you want to make client side communicator then use A1 as that is what the server sends.
            // The packet is encrypted part way through sesion id part. (Offset 7 or data offset 4...)
            if (this.key !== null) {
                if (startByte !== 0xB1) {
                    throw new Error("Expecting guard byte for encrypted packets from client to be 0xB1");
                }

                var receivedSequence = data.readUInt32LE(dataPosition);
                dataPosition += 4;
                
                if (receivedSequence != this.sequenceCount) {
                    console.warn("Received sequence not match.");
                }

                // Get the encrypted length.
                var encryptedSize = data.length - dataPosition;
                
                this.blowfish.decrypt(data.slice(dataPosition, dataPosition + encryptedSize));
                console.log("Decrypted\n"+hexy(data.slice(dataPosition, dataPosition + encryptedSize)));

                // The test decrypted packet should look like this.
                // d6 1c 00 0d 00 00 00 00 00 3b dd 00 00 01 08 00 09 00 03 1f 00 00 00 14 00 00 00 6b 00 00 00 00 c8 
                
                // Skip over the unencrypted guard byte and size. "Since we belive the decrypted data should fit into the first packet we should already have full size?"
                // TODO: Check this is true.

                // TODO: Ensure that the data position contains the d6 guard byte?
                // TODO: Ensure decrypted packet size is correct here?

                dataPosition += 3;

                // Get the Packet Type ID.
                output.packetTypeID = data.readUInt16LE(dataPosition); // TODO: This might actually be a byte.
                dataPosition += 2;
            } else {
                // Get the Packet Type ID.
                output.packetTypeID = data.readUInt16LE(dataPosition); // TODO: This might actually be a byte.
                dataPosition += 2;
            }

            // Get the session ID.
            output.sessionID = data.readUInt32LE(dataPosition);
            dataPosition += 4;

            // Note: We could detect the timestamp setting based off first packets size?

            // Get Timestamp?
            var expectingLength = 6;
            if (this.options.useTimestamp === true) {
                expectingLength += 4;
                if (data.length < 10) {
                    return cb(new Error("Expecting more data in packet."));
                }

                // Can we convert timestamp into date object?
                output.timestamp = data.readUInt32LE(dataPosition);
                dataPosition += 4;
            }

            // Note: Not sure if this covers all circumstances.
            if (data.length < expectingLength) {
                return cb(new Error("Expecting more data in packet."));
            }

            // Could consider this an error.
            // But whilst in development we will just warn to console.
            if (this.collection === null) {
                console.warn('Collection not specified on PacketTypeTransform Decoder.');
                return cb();
            }

            // Store the buffer into the packet output for debug reasons.
            output.buffer = data.slice(3);

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
            if (packetInfo === undefined) {
                // Note: In development mode it's going to be useful to output some info here.
                console.warn("Packet Type " + output.packetTypeID + " not found.", data);

                // TODO: Lets error?
                //return cb(new Error('Packet Type ' + output.packetTypeID + ' not found.'));

                // Whilst Developing, pass it on anyway as it could be handy to use the buffer to work out what the packet is...
                return cb(null, output);
            }

            // Read the correct length of bytes for flag size.
            if (packetInfo.flagSize === 1) {
                output.flagValue = data.readUInt8(dataPosition);
                dataPosition++;
            } else if (packetInfo.flagSize === 2) {
                output.flagValue = data.readUInt16LE(dataPosition);
                dataPosition += 2;
            } else if (packetInfo.flagSize === 4) {
                output.flagValue = data.readUInt32LE(dataPosition);
                dataPosition += 4;
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

                            if (fieldType === FieldType.PACKET) {
                                var [value, bytesRead] = readFieldFunction(packetInfo.structures[i], data, dataPosition, packetInfo.sizes[i]);
                            } else {
                                var [value, bytesRead] = readFieldFunction(data, dataPosition, packetInfo.sizes[i]);
                            }
                            

                            // Set field name in content if present.
                            var fieldName = packetInfo.names[i];
                            if (fieldName !== undefined) {
                                output.content[fieldName] = value;
                                console.log("Field: " + i + " " + fieldName + " = " + value);
                            } else {
                                // Just set it by index since we don't know the field name.
                                // We hope to recover all field names if possible.
                                output.content[i] = value;
                                console.log("Field: " + i + " = " + value);
                            }

                            dataPosition += bytesRead;
                        } catch (e) {
                            return cb(e);
                        }
                    }
                }
            }

            // Note: Client may send some padding bytes that I think we can ignore.

            // Move position after the packet we just processed.
            position += data.length + 1;

            // Push the parsed packet along.
            this.push(output);
        }

        cb();
    }
}

module.exports.Decoder = Decoder;

class PacketWriter {
    constructor(options) {
        // Note: Max size of buffer appears to be 2147483647.
        if (options.writeBufferLength === undefined) {
            options.writeBufferLength = 1024 * 4; // 104857600 ??
        }

        // Preallocate a buffer to store the WIP packet as it is constructed.
        this.writeBuffer = Buffer.allocUnsafe(options.writeBufferLength);

        this.collection = null;
        if (options.collection) {
            this.collection = options.collection;
        }

        // Older client did not do this.
        if (options.useTimestamp === undefined) {
            options.useTimestamp = true;
        }

        this.options = options;
    }

    // Turn hex dump into buffer to send.
    fakePacket(contents) {
        var buf = new Buffer(contents.replace(/[^0-9A-F]/gm, ''), "hex");
        return buf;
    }

    /* Returns a new buffer or throws an exception. */
    createPacket(packetTypeID, object = {}, forEncrypted = true) {
        var packetInfo = this.collection.get(packetTypeID);

        // If we can not find the collection then.
        if (packetInfo === null) {
            throw new Error('Packet info not found for PacketTypeID: ' + packetTypeID);
        }

        // TODO: Remove log.
        console.log("Creating Packet: "+packetTypeID+" "+(packetInfo.name || ''), object);

        var position = 0;

        // If creating a packet for encrypted usage, then leave a gap at the start for the encrypted data header.
        // Consisting of Guard Byte, short size, sequence, data, guard byte. Where the data has it's own guard bytes for some reason.
        if (forEncrypted) {
            position += 7;
        }

        // Increment space for guard byte.
        position += 1;

        // Increment space for packet size.
        position += 2;

        // Write packet type id.
        this.writeBuffer.writeUInt8(packetTypeID, position);
        position += 1;

        // Increment space for unknown byte.
        this.writeBuffer.writeUInt8(0, position);
        position += 1;

        // Write session id
        //this.writeBuffer.writeUInt32LE(100, position);
        //position += 4;
        // Increment space for session id.
        position += 4;

        if (this.options.useTimestamp === true) {
            // For some reason writing the time was out of bounds. Possibly because node.js has smaller safe integer size?
            //this.writeBuffer.writeUInt32LE((new Date()).getTime(), position);
            //this.writeBuffer.writeUInt32LE(this.sequenceCount % Number.MAX_SAFE_INTEGER, position);
            this.writeBuffer.writeUInt32LE(0, position);
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
            if (fieldType === FieldType.PACKET) {
                position += writeFieldFunction(packetInfo.structures[i], value, this.writeBuffer, position, packetInfo.sizes[i]);
            } else {
                position += writeFieldFunction(value, this.writeBuffer, position, packetInfo.sizes[i]);
            }
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
        // Encrypted packets should write the content length at offset 7 for the encapsulated packet.
        // Where as non encrypted should write at offset 1.
        // Encrypted packets will have a guard byte on the end with the real packet encapsulated.
        if (forEncrypted) {
            // Write unencrypted packet guard bytes.
            this.writeBuffer.writeUInt8(0xD6, 7);
            this.writeBuffer.writeUInt8(0x6B, position);

            // Increment space for this and final guard byte.
            position += 2;

            // Write the size of over-all and of the encrypted packet.
            this.writeBuffer.writeUInt16LE(position - 8, 8);

            // Clear the "last byte".
            this.writeBuffer.writeUInt8(0, position - 1);

            // Ensure there is padding up to 8 bytes for decryption on other end to work smoothly without overflowing into other data.
            var remainder = ((position - 8) % 8);
            if (remainder > 0) {
                var paddingLength = 8 - remainder;
                for (var i = 0; i<paddingLength; i++) {
                    this.writeBuffer.writeUInt8(0, position + i);
                }
            
                position += paddingLength;
            }

            this.writeBuffer.writeUInt16LE(position, 1);
            


        } else {
            // Increment space for guard byte.
            //this.writeBuffer.writeUInt8(this.endByte, position);
            position += 1;

            // Write Size.
            this.writeBuffer.writeUInt16LE(position, 1);
        }

        // Return a new buffer of our packet.
        var output = Buffer.from(this.writeBuffer.slice(0, position));

        console.info('Packet Made:\n' + hexy(output));

        return output;
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

        this.key = null;
        this.blowfish = new BlowFish();

        this.sequenceCount = 0;

        this.options = options;
    }

    setKey(key) {
        this.key = key;

        if (this.key !== null) {
            this.blowfish.setKey(key);
        }
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
        // Just pass the data on.
        cb(null, chunk);
    }

    /**
     * Create a packet from a packetTypeID and Object and send it to the client.
     * @param {Integer} packetTypeID 
     * @param {*} object 
     */
    send(packetTypeID, object) {
        // Some parts of the initial communication are not encrypted.

        var buffer = this.packetWriter.createPacket(packetTypeID, object, this.key !== null);
        this.sendPacket(buffer);
    }

    /**
     * Copy a packet to send, use this method when sending the same packet to multiple sockets.
     * @param {*} buffer 
     */
    sendPacketCopy(buffer) {
        var copy = Buffer.from(buffer);
        this.sendPacket(copy);
    }

    /**
     * The internal method for sending a packet.
     * @param {*} buffer 
     */
    sendPacket(buffer) {
        // Set the guard bytes correctly.
        // Set any packet increment or session id correctly.
        // Encrypt the buffer and copy contents from the cipher output.
        //console.info(hexy(buffer));

        if (this.options.useTimestamp === true) {
            // For some reason writing the time was out of bounds. Possibly because node.js has smaller safe integer size?
            //buffer.writeUInt32LE((new Date()).getTime(), position);
            // An encrypted packet would write this at offset 16 where as a non encrypted would be offset 9.
            buffer.writeUInt32LE(0, this.key !== null ? 16 : 9);
        }

        this.sessionID=0;

        if (this.key !== null)  {
            // Increment send counter.
            this.sequenceCount ++;

            // Write sequence
            buffer.writeUInt32LE(this.sequenceCount, 3);

            // Write Session ID.
            buffer.writeUInt32LE(this.sessionID, 12);

            var size = buffer.length - 8;
            var data = buffer.slice(7, buffer.length-1);

            // Write encrypted packet guard bytes. (Server only at the moment if wanting to make a packet client then you could change to B1, BF).
            buffer.writeUInt8(0xA1, 0);
            buffer.writeUInt8(0xAF, buffer.length -1);

            console.info("Before Encrypted Packet:\n" + hexy(buffer));

            this.blowfish.encrypt(data);
        } else {
            // Write unencrypted packet guard bytes.
            buffer.writeUInt8(0xD6, 0);
            buffer.writeUInt8(0x6B, buffer.length-1);

            buffer.writeUInt32LE(this.sessionID, 4);
        }

        console.info("Sending Packet:\n" + hexy(buffer));

        // Write the buffer out.
        this.write(buffer);
    }
}

module.exports.Encoder = Encoder;