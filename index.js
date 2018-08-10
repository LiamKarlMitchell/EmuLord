// TODO: Spawn processs as required?
// Use index.js as a master process to keep theo ther ones alive as needed?

const TCPServer = require('./module/net/TCPServer');

const { BlowFish }  = require('./module/crypt/bf_custom');

const fs = require('fs');
const hexy = require('hexy').hexy;

const cryptString = require('./module/crypt/string');
const STRINGCRYPTKEY = '12345678';

var debug = typeof v8debug === 'object' || /--debug|--inspect/.test(process.execArgv.join(' '));
if (debug === false) {
    var pino = require('pino')();
} else {
    // Nicer logging to read when debugging.
    var pino = {
        info: (...args)=>{
            
            args.forEach(a=>console.log((new Date()).toLocaleTimeString(), a));
            return;
        },
        error: (...args)=>{
            args.forEach(a=>console.error((new Date()).toLocaleTimeString(), a));
            return;
        }
    }
}

// TODO: Use glmatrix for their matrix and vec3 handling?
// http://glmatrix.net/

const { Deframer, Framer } = require('./module/net/FrameStreamTransform');
const { Collection, Structure, FieldType, Decoder, Encoder, PacketWriter, generateKey } = require('./module/net/PacketTypeTransform');
const crypto = require('crypto');

// TODO: Move these to different files / classes.
var loginServer = new TCPServer({port: 11002});

const PacketType = {
    "Config": 0x01,
    "Character": 0x02,
    "CharManager": 0x03,
    "Item": 0x04,
    "Skill": 0x05,
    "Shrine": 0x06,
    "PrivateTrade": 0x07,
    "Party": 0x08,
    "Party2": 0x09,
    "Auction": 0x0B,
    "SystemInfo": 0x0C,
    "LoginClient": 0x0D,
    "Chatting": 0x0F,
    "Timer": 0x11,
    "Admin": 0x12,
    "Quest": 0x13,
    "UIStatus": 0x14,
    "Guild": 0x15,
    "ItemConvert": 0x16,
    "Product": 0x17,
    "World": 0x18,
    "InterServerLink": 0x1A,
    "Character2": 0x1B,
    "Item2": 0x1F,
    "Skill2": 0x20,
    "Death": 0x21,
    "Login": 0x22,
    "Zoning": 0x23,
    "Admin2": 0x24,
    "Log": 0x27,
    "Guild2": 0x28,
    "CashMall": 0x2E,
    "ReturnToLogin": 0x2F,
    "EventNature": 0x30,
    "EventTeleport": 0x31,
    "EventSkillMaster": 0x3B,
    "EventManager": 0x3C,
    "EventQuest": 0x3E,
    "EventCharCustomize": 0x43,
    "SystemMessage": 0x44,
    "StartupEncryption": 0x48,
    "SiegeWar": 0x49,
    "PvP": 0x4A,
    "Ride": 0x4D,
    "BillInfo": 0x4E,
    "Summons": 0x4F,
    "GlobalChatting": 0x51,
    "Lord": 0x55,
    "BattleGround": 0x58,
    "Title": 0x60,
};

var collection = new Collection();

// Define all of the packet structures.
// Note: Fields are sent in reverse ordering.
// collection.add(PacketType.StartupEncryption, 'StartupEncryption', onStartupEncryption, [FieldType.INT8, FieldType.MEMORY_BLOCK], [1, 1], ['operation', 'key']);
// collection.add(PacketType.LoginClient, 'LoginClient', undefined, [FieldType.INT8], [1], 'operation');
// collection.add(PacketType.CharManager, 'CharManager', undefined, [FieldType.INT8, FieldType.CHAR, FieldType.INT32, FieldType.CHAR, FieldType.POS, FieldType.INT32], [1, 12, 1, 49, 1, 1, 1], ['operation', 'name', 'level', 'guild', 'location', 'zone', 'unknown']);

// TODO: Consider building packet type enumeration from collection based on structure name to id?


// TODO: Find if operation is present in all packets?
var StartupEncryption = new Structure("StartupEncryption")
    .operation()
    .memory_block(1, 'key');

collection.packet(PacketType.StartupEncryption, StartupEncryption);

// Define handlers for the Startup Encryption
StartupEncryption.operation(0, StartupEncryption_RequestEncryption);
StartupEncryption.operation(2, StartupEncryption_PublicKey);


// Receives operation 0.
// Responds with operation 1 and a key.
// Receives operation 2 and the clients key encrypted with servers key.
// Sends operation 3
// Turns on encrypt mode.  

// Note: If the client sends two packets quickly here then it will fail.

function StartupEncryption_RequestEncryption(socket, packet) {
    pino.info("StartupEncryption_RequestEncryption");

    if (socket.state.crypt === CryptState.None && packet.content.operation === CryptState.None) {
        generateKey().then(
            key => {

                // TODO: Remove this line, its here for debug purposes to use same hash each time on server.
                key = Buffer.from('12345678123456781234567812345678');

                // New Client only.
                // Set Algorithim type. 0 is Blowfish (default)
                // NONE: -1,
                // BLOWFISH: 0,
                // MD5MAC: 1,
                // RIJNDAEL: 2,
                // SEED: 3,
                // DYNCODE: 4,

                // Changing algo is untested currently. Maybe it is different args...
                var algoType = Buffer.alloc(8);
                //algoType.writeInt32LE(-1, 0);
                //algoType.writeUInt32LE(0, 4);
                algoType.writeUInt32LE(0, 0);
                algoType.writeUInt32LE(0, 4);
                
                // Note: I think these two packets should be sent on connection not on response from client, as the client could potentially never send this packet and then have no encryption at all.
                // Send the algo type to use.
                socket.send(PacketType.StartupEncryption, { operation: 0x06, key: algoType });

                // Send public key to client and set the key on the encoder.
                socket.send(PacketType.StartupEncryption, { operation: CryptState.Public, key: key });
                

                socket.state.key = key;
                socket.state.crypt = CryptState.Public;
            }
        ).catch(error => {
            console.error("Error starting up encryption: "+error);
            socket.close();
        });
    }

}

function StartupEncryption_PublicKey(socket, packet) {
    pino.info("StartupEncryption_PublicKey");

    if (socket.state.crypt === CryptState.Public && packet.content.operation === CryptState.Private) {
        if (packet.content.key.length !== 32) {
            throw new Error("Expecting client to send a key length of 32.");
        }

        var blowfish = new BlowFish();
        blowfish.setKey(socket.state.key);
        blowfish.decrypt(packet.content.key);

        // Set the key on the encoder.
        socket.encoder.setKey(socket.state.key);

        // Set the key on the decoder.
        socket.decoder.setKey(packet.content.key);

        // Send response of accepted.
        socket.send(PacketType.StartupEncryption, { operation: CryptState.Both });

        // Cleanup our temp var.
        delete socket.state.key;

        // Set encryption mode to on.
        socket.state.crypt = CryptState.Both;

    }

}


var LoginClient = new Structure("Login")
.operation()
.char(32)//.char(9)//
.char(49)
.int8(1)
.char(33)
.int8(1)
.int32(1)
.char(32)
.structure(new Structure()
    .char(23)
    .char(23)
    .char(23)
, 1)
.structure(new Structure()
    .int32(1)
    .char(49)
    .int32(1)
    .int32(1)
    .int32(1)
    .int32(1)
    .int32(1)
    .int32(1)
    .char(49)
, 1)
.int32(1)
.structure(new Structure('Version')
    .int32(1, 'Major')
    .int32(1, 'Minor')
 ,1)
.char(2049)
.char(5)
.int32(1)
.int32(1);

// 0 Encrypt Code
// 1 Sign on
// 2 E Key
// 3 Get Union?
// 6 Get Characters
// 8 Select Character
// 9 Return to Select World
// 10 Base Character of Race
// 11 Create Character
// 13 Remove Character
// 14 Rename Character
// 18 Character Compensation
// 19 Character Compensation

LoginClient.operation(0, LoginClient_ClientVersion);


function LoginClient_ClientVersion(socket, packet) {
    console.log("Client sends Version Info: " + packet.content.Version.Major + "." + packet.content.Version.Minor);

    // Invalid client version.
    //socket.send(PacketType.LoginClient, { operation: 32 });

    socket.send(PacketType.LoginClient, { operation: 0, 1: STRINGCRYPTKEY });
    //socket.send(PacketType.LoginClient, { operation: 13, 1: ' ' });
}

LoginClient.operation(1, LoginClient_Login);


function LoginClient_Login(socket, packet) {
    
    // Username: 2
    // UsernameLength 3
    // Password: 4
    // PasswordLength: 5
    // Unknown: 12

    // TODO: Check bounds of these values, to make sure user can't enter say (100000000) length and crash server.

    if (packet.content['3'] > 49) {
        throw new Error("Username length too long.");
    }

    if (packet.content['5'] > 33) {
        throw new Error("Password length too long.");
    }

    var username = cryptString.decipherText(packet.content['2'].substr(0, packet.content['3']), STRINGCRYPTKEY);
    var password = cryptString.decipherText(packet.content['4'].substr(0, packet.content['5']), STRINGCRYPTKEY)

    console.log("Login Received for "+username);

    socket.send(PacketType.LoginClient, { operation: 1 });

    
    return;
    // TODO: Remove this hard coded sending its just for testing purposes.
    socket.fakePacket(`
        D6 1A 00 0D 00 00 00 00 00 00 00 00 00 03 00 00
        31 32 33 34 35 36 37 38 00 6B        
     `);
    
    // Login Response
    socket.fakePacket(`
        D6 4A 00 0D 00 00 00 00
        00 00 00 00 00 05 C0 01
        75 73 65 72 31 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 6B
        `);

    // Server List
    socket.fakePacket(`
        D6 27 00 18 00 00 00 00 00 00 00 00 00 09 02 15
        00 54 65 73 74 3D 45 6D 75 6C 61 74 6F 72 3D 30
        3D 31 3D 30 3B 00 6B
        `);

    // Other server thing?
    socket.fakePacket(`
        D6 3A 00 18 00 00 00 00
        00 00 00 00 00 0B 04 75
        73 65 72 31 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 08
        00 54 65 73 74 3D 33 3B
        00 6B                  
        `);

    // Server List
    socket.fakePacket(`
        D6 27 00 18 00 00 00 00 00 00 00 00 00 09 02 15
        00 54 65 73 74 3D 45 6D 75 6C 61 74 6F 72 3D 30
        3D 31 3D 30 3B 00 6B
        `);

    // Characters
    socket.fakePacket(`
        D6 19 00 0D 00 00 00 00
        00 00 00 00 00 01 01 03
        06 00 10 00 01 00 00 00
        6B           
        `);    

    socket.fakePacket(`
        D6 4E 00 0D 00 00 00 00
        00 00 00 00 00 01 01 04
        3B 00 0E 00 48 61 72 64
        64 65 61 74 68 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 09 03 00 00
        00 00 00 00 00 6B 
    `);
    socket.fakePacket(`
        D6 4E 00 0D 00 00 00 00
        00 00 00 00 00 01 01 04
        3B 00 0E 00 54 65 73 74
        31 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 05 03 00 00
        00 01 00 00 00 6B 
        `);

    socket.fakePacket(`
        D6 4E 00 0D 00 00 00 00
        00 00 00 00 00 01 01 04
        3B 00 0E 00 54 65 73 74
        32 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 05 03 00 00
        00 01 00 00 00 6B     
        `);

    // user details?
    socket.fakePacket(`
        D6 42 00 0D 00 00 00 00
        00 00 00 00 00 05 00 05
        75 73 65 72 31 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 6B  
        `);

    socket.fakePacket(`
        D6 1B 00 04 00 00 00 00
        00 00 00 00 00 11 00 40
        00 13 65 00 00 00 00 00
        00 00 6B       
    `);        
        
    socket.fakePacket(`
        D6 E9 01 02 00 00 00 00
        00 00 00 00 00 BF 9F BE
        2F 00 65 00 00 00 09 00
        00 00 09 00 48 61 72 64
        64 65 61 74 68 01 2B 00
        FF 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 04 00 2E 01 9F 0B 89
        00 96 0B 2A 00 DF 0B 20
        03 00 00 BC 02 00 00 A4
        06 00 00 20 03 00 00 00
        00 00 00 40 06 00 00 6E
        00 00 00 D0 07 00 00 70
        17 00 00 00 00 00 00 0D
        00 07 03 00 00 00 02 00
        00 00 04 00 00 00 16 00
        1F 00 40 00 00 00 2B 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 09 00
        03 02 00 00 00 02 00 00
        00 0D 00 03 06 00 01 00
        00 00 00 00 02 00 00 00
        0D 00 07 64 00 00 00 32
        00 00 00 3C 00 00 00 09
        00 A0 00 00 00 00 00 00
        00 00 2A 00 DF 0B 20 03
        00 00 BC 02 00 00 A4 06
        00 00 20 03 00 00 00 00
        00 00 40 06 00 00 6E 00
        00 00 D0 07 00 00 70 17
        00 00 00 00 00 00 0D 00
        07 03 00 00 00 02 00 00
        00 04 00 00 00 18 00 1F
        00 00 00 40 00 00 00 2B
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 16
        00 1F 00 40 00 00 00 2B
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 09
        00 03 02 00 00 00 02 00
        00 00 0D 00 03 06 00 01
        00 00 00 00 00 02 00 00
        00 0D 00 07 64 00 00 00
        32 00 00 00 3C 00 00 00
        09 00 A0 00 00 00 00 00
        00 00 00 A4 A2 7D 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 03 00 20 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        0F FF 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        6B              
    `);         

}


collection.packet(PacketType.LoginClient, LoginClient);




// TODO: Make this definable through chainable functions.
// Maybe something like this?
// Collection.define('Name', PacketTypeID)
//           .operations({ value: Function }) // A macro for uint8('operation',1) but also allows for adding method to call to handle certian operation values.
//           .handler(value, Function) // The handler for managing the function onReceive to be used if there is no operations uint8 at front.
//           .int8('Name')
//           .char('Name', size = 1)
//           .block('Name')
//           .vec3('Location')
//           .structure('Name', 'StructureName')

// Structures would also be stored in the collection on a structures object keyed by name.



var LoginOperations = {
    "EncryptCode": 0x00,
    "SignOn": 0x01,
    "Ekey": 0x02,
    "UnionInfo": 0x03,
    "CharacterName": 0x04,
    "CharacterNameFinish": 0x05,
    "CharacterInfo": 0x06,
    "CharacterInfoFinish": 0x07,
    "EnterGame": 0x08,
    "ReturnToSelectWorld": 0x09,
    "RaceBase": 0x0A,
    "NewCharacterName": 0x0B,
    "NewCharacterInfoFinish": 0x0C,
    "RemoveCharacter": 0x0D,
    "RenameCharacter": 0x0E,
    "LoginResult": 0x0F,
    "RemoveDuplicatedAccount": 0x10,
    "CompensationInfo": 0x11,
    "CompensationCharacterSelect": 0x12,
    "CompensationCharacterCancel": 0x13,
    "CouponInfo": 0x14,
    "CreateCharacter": 0x15,
    "RemoveDuplicatedAccountForLoginserver": 0x16,
    "InvalidClientVersion": 0x20,
};



// TODO: See if we can make a nicer way to handle/define the packets and functions for handling them.
// TODO: Decide if we can have a way to enable/disable some of the packets if they are received and client is not Setup with Encryption, Authenticated, In a guild, In a party etc.....
//       Possibly something like. socket.state === SocketState.BrandNew, SocketState.Ready, SocketState.LoggedIn ? etc... a bit mask would work nicer actually if we want to do things like in guild and in party, or we just make generic function enabler check functions....
// Maybe a file per each ID?
// Example: Packets/0F_Chatting.js

const ServerType = {
    None: 0,
    Login: 1,
    Character: 2,
    World: 3,
    Transfering: 4,
};

const CryptState = {
    None: 0,
    Public: 1,
    Private: 2,
    Both: 3,
};

loginServer.on('connection', (socket) => {
    // Handle the socket's stream.

    // TODO: Get IPv4 address and port reliably. (I coded this already in another project)
    pino.info("Socket has connected.");

    // Our session should have a state of some kind.
    socket.state = {
        authenticated: false,
        crypt: CryptState.None,
        serverType: ServerType.None
    };

    // Our session should have auth info.
    socket.user = {
        id: null,
        name: '',
    };

    // TODO: A way to kick zombie sockets. (Sockets that don't do anything in quite a long time)
    // Inactivity timeout
    // socket.setInactivityTimer = function() {
    //     clearTimeout(socket.inactiveTimer);
    //     socket.inactiveTimer = setTimeout(()=>{
    //         socket.close();
    //     }, 60000); // 1 minute.
    // }.bind(socket);
    // Simply call socket.setInactivityTimer() when you have activity?

    // Communication between client and server will be encrypted.
    socket.serverEncryptionKey = null;
    socket.clientEncyrptionKey = null;

    // We must take the stream of bytes and turn it back into packets.

    // And we need a way to decode those packets into something we can use and take care of any decryption.
    var decoder = new Decoder({ collection: collection });
    socket.decoder = decoder;

    // And we need a way to take packet objects and turn them back into bytes including any encryption required.
    var encoder = new Encoder({ collection: collection });
    socket.encoder = encoder;

    // TODO: Consider if we want to change the collection to based on if the client is authed or not etc...

    // Pipe the incomming data from the socket into the decoder to be parsed as packets and handled accordingly.
    socket.pipe(decoder);

    // Pipe data sent with the encoder through to the socket.
    encoder.pipe(socket);

    // Please for-go the use of socket.write, recommend to use socket.send or socket.sendPacket.
    // Send to be used to make and send a packet to the client.
    // Send Packet is used to send an already seralized packet (created by PacketWriter.createPacket, or socket.writer.packetWriter.createPacket)
    // as sending in that way may need to add per socket session data to the packet prior to sending it on.

    // A special writer to send our packets through to the socket.
    socket.send = function socket_send(packetID, object) {
        encoder.send(packetID, object);
    }

    // A special writer for buffer data we want to send to the client, with any encryption over the structure as required.
    socket.sendPacket = function socket_sendPacket(data) {
        encoder.sendPacket(data);
    }

     /**
     * Copy a packet to send, use this method when sending the same packet to multiple sockets.
     * @param {*} buffer 
     */
    socket.sendPacketCopy = function socket_sendPacketCopy(buffer) {
        encoder.sendPacketCopy(buffer);
    }

    // Turn hex dump into buffer to send.
    socket.fakePacket = function socket_fakePacket(contents) {
        var buf = Buffer.from(contents.replace(/[^0-9A-F]/gm, ''), "hex");

        if (this.encoder.key !== null) {
            // Ensure there is padding up to 8 bytes for decryption on other end to work smoothly without overflowing into other data.
            var remainder = ((buf.length - 8) % 8);
            var paddingLength;
            if (remainder > 0) {
                paddingLength = 8 - remainder;
            } else {
                paddingLength = 0;
            }

            var endOfInputBufferPosition = 7 + buf.length;
            var buf2 = Buffer.alloc(endOfInputBufferPosition + paddingLength + 1);
            buf.copy(buf2, 7);

            buf2.writeUInt16LE(buf2.length, 1);

            for (var i=0; i<paddingLength; i++) {
                buf2.writeUInt8(0, endOfInputBufferPosition + i);
            }

            this.sendPacket(buf2);
        } else {
            this.sendPacket(buf);
        }
    }

    // A helper function to send a system chat message to the client.
    socket.writeMessage = function socket_writeMessage(message) {
        // A way to send chat message to client easily for system messages.
        encoder.send(PacketType.Chatting, { name: 'System', message: message });
    }

    socket.onUnhandledPacket = function socket_onUnhandledPacket(socket, packet) {
        pino.warn("Unhandled packet: ", hexy(packet.buffer), packet);
    }

    // Handle completed packets the client sends to us.
    decoder.on('data', (packet) => {
        console.log('RECV DATA: ');
        pino.info("Packet TypeID: " + packet.packetTypeID + " Session: " + packet.sessionID + " Timestamp: " + packet.timestamp, packet.content);

        try {
            // If the packet info could not be obtained for whatever reason then call the unhandled packet function.
            if (packet.info === undefined) {
                socket.onUnhandledPacket(socket, packet);
                return;
            }

            // TODO: Ensure the socket is in a state allowed to handle this packet.

            // If the packet info handler is set then call it.
            if (packet.info.handler) {
                packet.info.handler(socket, packet);
            } else {
                // Otherwise we can't handle the packet.
                socket.onUnhandledPacket(socket, packet);
            }
        }
        catch (err) {
            // TODO: Handle packet logic error.
            pino.error(err);
        }

    });

    // TODO: Handle any errors on our custom streams?
    decoder.on('error', (error) => {
        pino.error(error);
    })
    encoder.on('error', (error) => {
        pino.error(error);
    })

    socket.on('close', (hasError) => {
        pino.info('Socket has disconnected.');
    });

    // Set the server type of the socket.
    socket.serverType = ServerType.Login;
});

loginServer.on('error', (error) => {
    pino.error("Login Server error ", error);
});

var gameServer = new TCPServer({port: 11008});

gameServer.on('error', (error) => {
    pino.error("Game Server error ", error);
});

// TODO: Generalize the above from login server and make it available for game server.

//https://www.youtube.com/watch?v=QuoKNZjr8_U
pino.info("I'ts alive!");