// TODO: Name on fields should be unique.
// TODO: To and From methods to translat between bytes and JS object? For example if something is a date/time?


class Structure {
    constructor(name, id) {
        if (name === undefined) {
            throw new Error("Structure name is required.");
        }

        if (id === undefined) {
            throw new Error("Structure id is required.");
        }

        this.name = name;
        this.id = id;
        this.fields = [];
        this.flagsLength = 0;
        
        this.onReceive = null;
        this.handlers = {};

        // Next step calculate the flags length.
        setTimeout(calculateFlagsLength.bind(this), 0);
    }

    calculateFlagsLength() {
        this.flagsLength = this.fields.length % 8;

        if (this.flagsLength !== 1 || this.flagsLength !== 2 || this.flagsLength !== 4) {
            throw new Error("Structure Name: " + this.name + " expecting flag length of structures to be 1, 2 or 3 bytes in length so a max of 32 fields per structure.");
        }
    }

    operators(hanlders) {
        this.fields.push({
            type: FieldType.UINT8,
            name: 'operators',
            size: 1
        });

        this.handlers = handlers;
    }

    // Protocol supported data types.
    char(name, size = 1) {
        this.fields.push({
            type: FieldType.CHAR,
            name: name,
            size: size
        });
    }

    int8(name) {
        this.fields.push({
            type: FieldType.INT8,
            name: name,
            size: 1
        });
    }

    uint8(name) {
        this.fields.push({
            type: FieldType.UINT8,
            name: name,
            size: 1
        });
    }

    int16(name) {
        this.fields.push({
            type: FieldType.INT16,
            name: name,
            size: 1
        });
    }

    uint16(name) {
        this.fields.push({
            type: FieldType.UINT16,
            name: name,
            size: 1
        });
    }

    int32(name) {
        this.fields.push({
            type: FieldType.INT32,
            name: name,
            size: 1
        });
    }

    uint32(name) {
        this.fields.push({
            type: FieldType.UINT32,
            name: name,
            size: 1
        });
    }

    int64(name) {
        this.fields.push({
            type: FieldType.INT64,
            name: name,
            size: 1
        });
    }

    uint64(name) {
        this.fields.push({
            type: FieldType.UINT64,
            name: name,
            size: 1
        });
    }

    float(name) {
        this.fields.push({
            type: FieldType.FLOAT,
            name: name,
            size: 1
        });
    }

    vec3(name) {
        this.fields.push({
            type: FieldType.VEC3,
            name: name,
            size: 1
        });
    }

    matrix(name) {
        this.fields.push({
            type: FieldType.MATRIX,
            name: name,
            size: 1
        });
    }

    structure(name, structureName) {
        if (structureName === undefined) {
            throw new Error("Structure, structure name is required.");
        }

        this.fields.push({
            type: FieldType.PACKET,
            name: name,
            structureName: structureName
            size: 1
        });
    }

    memory_block(name) {
        this.fields.push({
            type: FieldType.MEMORY_BLOCK,
            name: name,
            size: 1
        });
    }

    vec3extra(name, size = 1) {
        this.fields.push({
            type: FieldType.VEC3EXTRA,
            name: name,
            size: size
        });
    }

    wchar(name, size = 1) {
        this.fields.push({
            type: FieldType.WCHAR,
            name: name,
            size: size
        });
    }

}

module.exports.Structure = Structure;