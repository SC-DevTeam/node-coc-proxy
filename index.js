'use strict';

var net = require('net');
var fs = require('fs');
var util = require('util');
var path = require('path');
var jsome = require('jsome');
var options = require('./util/usage').options;
var settings = require('./settings.json');

require('console-stamp')(console, 'yyyy-mm-dd HH:MM:ss');

var PacketReceiver = require('./lib/packetreceiver');
var ClientCrypto = require('./lib/client/crypto');
var ServerCrypto = require('./lib/server/crypto');
var Definitions = require('./lib/definitions');
var EMsg = require('./enums/emsg');

var definitions = new Definitions(options);
var clients = {};

const banner = new Buffer("0d0a205f5f5f5f5f205f5f5f5f5f5f5f5f5f5f5f2020202020202020205f5f5f5f5f20202020202020202020202020202020202020200d0a2f20205f5f5f2f20205f5f205c20205f20205c202020202020207c5f2020205f7c202020202020202020202020202020202020200d0a5c20602d2d2e7c202f20205c2f207c207c207c5f5f5f5f5f2020205f7c207c205f5f5f20205f5f205f205f205f5f205f5f5f20200d0a20602d2d2e205c207c2020207c207c207c202f205f205c205c202f202f207c2f205f205c2f205f60207c20275f2060205f205c200d0a2f5c5f5f2f202f205c5f5f2f5c207c2f202f20205f5f2f5c2056202f7c207c20205f5f2f20285f7c207c207c207c207c207c207c0d0a5c5f5f5f5f2f205c5f5f5f5f2f5f5f5f2f205c5f5f5f7c205c5f2f205c5f2f5c5f5f5f7c5c5f5f2c5f7c5f7c207c5f7c207c5f7c0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200d0a202020205f5f5f5f5f205f5f5f5f5f205f5f5f5f5f205f5f5f5f5f5f2020202020202020202020202020202020202020202020200d0a2020202f20205f5f205c20205f20202f20205f5f205c7c205f5f5f205c20202020202020202020202020202020202020202020200d0a2020207c202f20205c2f207c207c207c202f20205c2f7c207c5f2f202f205f5f205f5f5f5f5f20205f5f5f2020205f20202020200d0a2020207c207c2020207c207c207c207c207c202020207c20205f5f2f20275f5f2f205f205c205c2f202f207c207c207c202020200d0a2020207c205c5f5f2f5c205c5f2f202f205c5f5f2f5c7c207c20207c207c207c20285f29203e20203c7c207c5f7c207c202020200d0a202020205c5f5f5f5f2f5c5f5f5f2f205c5f5f5f5f2f5c5f7c20207c5f7c20205c5f5f5f2f5f2f5c5f5c5c5f5f2c207c202020200d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020205f5f2f207c202020200d0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020207c5f5f5f2f2020202020", "hex");

if(options.replay) {
    fs.readFile(options.replay.filename, {encoding: "binary"}, function(err, contents) {
        if(err) {
            return console.error(err);
        }
        var message = {
            messageType: parseInt(path.basename(options.replay.filename, ".bin")),
            decrypted: contents
        };

        definitions.decode(message);
        if(message.decoded) {
            jsome(message.decoded);
        }
    });
} else {
    var server = net.createServer();

    server.on('error', function(err) {
        if (err.code == 'EADDRINUSE') {
            console.log('Address in use, exiting...');
        } else {
            console.log('Unknown error setting up proxy: ' + err);
        }

        process.exit(1);
    });

    server.on('listening', function() {
        console.log('listening on ' + server.address().address + ':' + server.address().port);
        console.log(banner.toString("utf8"));
    });

    server.on('connection', function(socket) {
        var gameserver = new net.Socket();
        socket.key = socket.remoteAddress + ":" + socket.remotePort;
        clients[socket.key] = socket;

        var clientPacketReceiver = new PacketReceiver();
        var serverPacketReceiver = new PacketReceiver();

        var clientCrypto = new ClientCrypto(settings);
        var serverCrypto = new ServerCrypto(settings);

        clientCrypto.setServer(serverCrypto);
        serverCrypto.setClient(clientCrypto);

        console.log('new client ' + socket.key + ' connected, establishing connection to game server');

        gameserver.connect(9339, "gamea.clashofclans.com", function() {
            console.log('Connected to game server on ' + gameserver.remoteAddress + ':' + gameserver.remotePort);
        });

        gameserver.on("data", function(chunk) {
            serverPacketReceiver.packetize(chunk, function(packet) {
                var message = {
                    'messageType': packet.readUInt16BE(0),
                    'length': packet.readUIntBE(2, 3),
                    'version': packet.readUInt16BE(5),
                    'payload': packet.slice(7, packet.length)
                };

                console.log('[SERVER] ' + (EMsg[message.messageType] ? EMsg[message.messageType] + ' [' + message.messageType + ']' : message.messageType));

                clientCrypto.decryptPacket(message);

		console.log("[SERVER DECRYPTED]: " + new Buffer(message.decrypted).toString('hex'));

                if(options.dump) {
                    fs.writeFile(options.dump.filename + "/" + message.messageType + ".bin", Buffer.from(message.decrypted), {encoding: "binary"}, function(err) {
                        if(err) {
                            console.error(err);
                        }
                    });
                }

                definitions.decode(message);

                if(options.verbose && message.decoded && Object.keys(message.decoded).length) {
                    jsome(message.decoded);
                }

                serverCrypto.encryptPacket(message);

                var header = Buffer.alloc(7);

                header.writeUInt16BE(message.messageType, 0);
                header.writeUIntBE(message.encrypted.length, 2, 3);
                header.writeUInt16BE(message.version, 5);

                clients[socket.key].write(Buffer.concat([header, Buffer.from(message.encrypted)]));
            });
        });

        gameserver.on("end", function() {
            console.log('Disconnected from game server');
        });

        clients[socket.key].on('data', function(chunk) {
            clientPacketReceiver.packetize(chunk, function(packet) {
                var message = {
                    'messageType': packet.readUInt16BE(0),
                    'length': packet.readUIntBE(2, 3),
                    'version': packet.readUInt16BE(5),
                    'payload': packet.slice(7, packet.length)
                };

                console.log('[CLIENT] ' + (EMsg[message.messageType] ? EMsg[message.messageType] + ' [' + message.messageType + ']' : message.messageType));

                serverCrypto.decryptPacket(message);

                if(options.dump) {
                    fs.writeFile(options.dump.filename + "/" + message.messageType + ".bin", Buffer.from(message.decrypted), {encoding: "binary"}, function(err) {
                        if(err) {
                            return console.log(err);
                        }
                    });
                }

                //definitions.decode(message);

                if(options.verbose && message.decoded && Object.keys(message.decoded).length) {
                    //jsome(message.decoded);
                }

                console.log('[CLIENT DECRYPTED]: ' + new Buffer(message.decrypted).toString('hex'));

                clientCrypto.encryptPacket(message);

                var header = Buffer.alloc(7);

                header.writeUInt16BE(message.messageType, 0);
                header.writeUIntBE(message.encrypted.length, 2, 3);
                header.writeUInt16BE(message.version, 5);

                gameserver.write(Buffer.concat([header, Buffer.from(message.encrypted)]));
            });
        });

        clients[socket.key].on('end', function() {
            console.log('Client ' + socket.key + ' disconnected from proxy.');
            delete clients[socket.key];
            gameserver.end();
        });
    });

    server.listen({ host: '0.0.0.0', port: 9339, exclusive: true }, function(err) {
        if (err) {
            console.log(err);
        }
    });
}
