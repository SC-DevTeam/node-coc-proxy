'use strict';

var nacl = require("tweetnacl");
var blake2 = require("blake2");
var ByteBuffer = require("../../util/bytebuffer-sc");
var EMsg = require('../../enums/emsg');
const Crypto = require('../crypto.js');
const Nonce = require('../nonce.js');

class ServerCrypto extends Crypto {
    constructor(settings) {
        super();
        this.publicServerKey = new Buffer(settings.serverKey, "hex");
        this.magicKey = new Buffer("56b577a8996f52c388981942811c6e9b8d39dc3e281f1ce0c047a3d8e55cb222", "hex");
    }

    setClient(client) {
        this.client = client;
    }

    decryptPacket(message) {
        if (message.messageType == EMsg.ClientHello) {
            message.decrypted = message.payload;
        } else if (message.messageType == EMsg.Login) {
            this.clientKey = message.payload.slice(0, 32);
            var cipherText = message.payload.slice(32);

            this.setSharedKey(this.magicKey)
            var nonce = new Nonce({ clientKey: this.clientKey, serverKey: this.publicServerKey });

            message.decrypted = this.decrypt(cipherText, nonce);

            if (message.decrypted) {
                this.setSessionKey(Buffer.from(message.decrypted.slice(0, 24)));
                this.setDecryptNonce(Buffer.from(message.decrypted.slice(24, 48)));
                this.client.setEncryptNonce(Buffer.from(message.decrypted.slice(24, 48)));

                message.decrypted = message.decrypted.slice(48);
            }
        } else {
            message.decrypted = this.decrypt(message.payload);
        }
    }

    encryptPacket(message) {
        if (message.messageType == EMsg.ServerHello || (message.messageType == EMsg.LoginFailed && !this.getSessionKey())) {
            message.encrypted = message.decrypted;
        } else if (message.messageType == EMsg.LoginOk || message.messageType == EMsg.LoginFailed) {
            var nonce = new Nonce({ clientKey: this.clientKey, serverKey: this.publicServerKey, nonce: this.decryptNonce });

            this.setSharedKey(this.magicKey)

            var toEncrypt = Buffer.concat([this.encryptNonce.getBuffer(), this.getSharedKey(), Buffer.from(message.decrypted)]);
            var cipherText = this.encrypt(toEncrypt, nonce);

            message.encrypted = cipherText;
        } else {
            message.encrypted = this.encrypt(message.decrypted);
        }
    }
}

module.exports = ServerCrypto;
