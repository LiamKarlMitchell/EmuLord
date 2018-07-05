// TODO: Spawn processs as required?
// Use index.js as a master process to keep theo ther ones alive as needed?

const TCPServer = require('./module/net/TCPServer');

const fs = require('fs');
const hexy = require('hexy').hexy;

var pino = require('pino')();

// TODO: Use glmatrix for their matrix and vec3 handling?
// http://glmatrix.net/


// function onFile(err, data) {
//     if (err) {
//         console.error(err);
//     }

//     var result = processData(data);
//     console.log(JSON.stringify(result, true, 4));
// }

const { Deframer, Framer } = require('./module/net/FrameStreamTransform');
const { Collection, FieldType, Decoder, Encoder, PacketWriter } = require('./module/net/PacketTypeTransform');


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
    "Party": 0x09,
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
    "Character": 0x1B,
    "Item": 0x1F,
    "Skill": 0x20,
    "Death": 0x21,
    "Login": 0x22,
    "Zoning": 0x23,
    "Admin": 0x24,
    "Log": 0x27,
    "Guild": 0x28,
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
    "EmuLord": 0x55,
    "BattleGround": 0x58,
    "Title": 0x60,
};

var collection = new Collection();

// Define all of the packet structures.
collection.add(PacketType.StartupEncryption, 'StartupEncryption', onStartupEncryption, [FieldType.INT8, FieldType.MEMORY_BLOCK], [1, 1], ['operation', 'key']);
collection.add(PacketType.Login, 'Login', undefined, [FieldType.INT8], [1], 'operation');
collection.add(PacketType.CharManager, 'CharManager', undefined, [FieldType.INT8, FieldType.CHAR, FieldType.INT32, FieldType.CHAR, FieldType.POS, FieldType.INT32], [1, 12, 1, 49, 1, 1, 1], ['operation', 'name', 'level', 'guild', 'location', 'zone', 'unknown']);


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




var p = new PacketWriter({ collection: collection });

// console.log(hexy(p.createPacket(PacketType.StartupEncryption, { operation: 1, key: new Buffer('This is a test') })));
// process.exit(0);


function onStartupEncryption(socket, packet) {
    pino.info("Socket has sent us a startup encryption packet.", packet);

    // Receives operation 0.
    // Responds with operation 1 and a key.
    // Receives operation 2 and the clients key encrypted with servers key.
    // Sends operation 3
    // Turns on encrypt mode.  

    if (socket.state.crypt === CryptState.None && packet.operation === CryptState.None) {
        socket.writer.getKey().then(
            key => {
                socket.send(PacketType.StartupEncryption, { operation: CryptState.Public, key: key });
                socket.writer.setKey(key);
            }
        ).error(error => {
            console.error("Error starting up encryption: "+error);
            socket.close();
        });
    } else if (socket.state.crypt === CryptState.Public && packet.operation === CryptState.Private) {
        socket.send(PacketType.StartupEncryption, { operation: CryptState.Both });

        // Decrypt the clients key and set it on the reader.
        // socket.writer.getKey()
        //(packet.key, 32)
        //socket.reader.setKey(key);

        // Set encryption mode to on.
        socket.state.crypt = CryptState.Both;
    } else {
        throw new Error("Invalid crypt negiotate state.");
    }

}


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
    var deframer = new Deframer();

    // And we need a way to decode those packets into something we can use and take care of any decryption.
    var decoder = new Decoder({ collection: collection });
    socket.decoder = decoder;

    // And we need a way to take packet objects and turn them back into bytes including any encryption required.
    var encoder = new Encoder({ collection: collection });
    socket.encoder = encoder;

    // TODO: Consider if we want to change the collection to based on if the client is authed or not etc...

    // And send those bytes back over the stream framed up.
    var framer = new Framer();

    // Pipe the incomming data from the socket into the deframer and then into the decoder.
    socket.pipe(deframer)
          .pipe(decoder);

    // Pipe any bytes sent to the encoder through the framer out to the socket.
    encoder.pipe(framer).pipe(socket);

    // A special writer to send our packets through to the socket.
    socket.write = function socket_write(packetID, object) {
        encoder.write(packetID, object);
    }

    // A special writer for buffer data we want to send to the client, with any encryption over the structure as required.
    socket.writeBuffer = function socket_writeBuffer(data) {
        encoder.writeBuffer(data);
    }

    socket.writeBypassEncoder = function socket_writeBypassEncoder(data) {
        framer.write(data);
    }

    socket.writeMessage = function socket_writeMessage(message) {
        // A way to send chat message to client easily for system messages.
        encoder.write(PacketType.Chatting, { name: 'System', message: message });
    }

    socket.onUnhandledPacket = function socket_onUnhandledPacket(socket, packet) {
        pino.warn("Unhandled packet: ", hexy(packet.buffer), packet);
    }

    // Handle completed packets the client sends to us.
    decoder.on('data', (packet) => {
        console.log('RECV DATA: ');
        pino.info(packet);

        try {
            // If the packet info could not be obtained for whatever reason then call the unhandled packet function.
            if (packet.info === undefined) {
                this.onUnhandledPacket(socket, packet);
                return;
            }

            // TODO: Ensure the socket is in a state allowed to handle this packet.

            // If the packet info handler is set then call it.
            if (packet.info.handler) {
                packet.info.handler(socket, packet);
            } else {
                // Otherwise we can't handle the packet.
                this.onUnhandledPacket(socket, packet);
            }
        }
        catch (err) {
            // TODO: Handle packet logic error.
            pino.error(err);
        }

    });

    // TODO: Handle any errors on our custom streams?
    deframer.on('error', (error) => {
        pino.error("deframer error: ", error);
    })
    decoder.on('error', (error) => {
        pino.error("decoder error: ", error);
    })
    encoder.on('error', (error) => {
        pino.error("encoder error: ", error);
    })
    framer.on('error', (error) => {
        pino.error("framer error: ", error);
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