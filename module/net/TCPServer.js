const net = require('net');
const uuidv4 = require('uuid/v4');

// A light weight wrapper around TCP net server.
class TCPServer extends net.Server {
    constructor(opts = {}) {
        if (opts === undefined) {
            opts = {};
        }

        if (opts.port === undefined) {
            throw new Error("TCP Server expects a port to be set.");
        }

        if (opts.bindIP === undefined) {
            // Bind on all network interfaces by default.
            opts.bindIP = '0.0.0.0';
        }

        super(opts);

        // Note: If you want to do something else upon a connection you could simply set another handler for connection.
        this.on('connection', (socket) => {
            this.setup(socket);
        });

        this.listen(opts.port, opts.bindIP);
    }

    setup(socket) {
        // Disable nagle.
        socket.setNoDelay(true);

        // Give each socket a Unique ID.
        socket.uniqueid = uuidv4();

        socket.on('error', error => this.onSocketError(socket, error));
        socket.on('close', hadError => this.onSocketClose(socket, hadError));
    }

    onSocketError(socket, error) {
        // I don't really consider a connection reset as something to complain about it's pretty normal behaviour?
        if (error.code === 'ECONNRESET') {
            return;
        }

        console.log("Socket Error: ", error);
    }

    onSocketClose(socket, hadError) {
        // After 1 ms remove all listeners from the socket.
        // This lets other close listeners get triggered.
        setTimeout(()=>{
            socket.removeAllListeners();
        }, 1);
    }
}

module.exports = TCPServer;