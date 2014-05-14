/* Message types:
 - info : message sent by server to go in info box, in green
 - error : error sent by server to go in infp box, in red
 - sendclear : message sent by client in clear text
 - cryptmsg : message sent by client encrypted
 - testcrypt : message sent as soon as we receive server's pubkey to test if the client correctly encrypts for server 
 - server_pubkey_pem : the pubkey to encrypt when communicating with server
 - contact_pubkey : the pubkey to encrypt when communicating with contact
 */

// Very first variables
var VERSION = "0.0.1";

// First write a line to console 
// so that the logfile is immediately written
console.log("----- Cryptweet-v" + VERSION + " starting at " + new Date().toTimeString() + " -----");

// Require everything we need...
var express = require("express");
var fs = require('fs');
var forge = require('node-forge');

// Set vars
var port = 3700;
var logged_in_users = [];
var server_pubkey_pem = false;

// Create object
var app = express();

/* Set template engine infos */
app.set('views', __dirname + '/tpl');
app.set('view engine', "jade");
app.engine('jade', require('jade').__express);
app.use(express.static(__dirname + '/public'));
app.get("/test", function(req, res) {
    TESTMODE = true;
    res.render("test");
});
app.get("/login2", function(req, res) {
    res.render("login2");
});
app.get("/login", function(req, res) {
    res.render("login");
});
app.get("/", function(req, res) {
    res.render("login");
});


/* SERVER FUNCTIONS */
function myLog(logObj) {
    if (typeof logObj === "string")
    {
        console.log("\n :: " + new Date().toISOString() + " :: " + logObj);
    } else {
        console.log(logObj);
    }
}

function broadcrypt(json_object) {
    if (typeof io.sockets !== undefined)
    {
        // GET CONNECTED CLIENTS
        var clients = io.sockets.clients();
        for (var c in clients) {
            var client = clients[c];
            if (typeof client.cryptweet_user_puk !== 'undefined' && client.cryptweet_user_puk !== false)
            {
                sendClient(client, json_object);
            } else {
                myLog("broadcrypt  :: client [" + client.id + "] doesn't have cryptweet_user_puk : ");
            }
        }
    }
}

function sendClient(tmpSocket, json_object) {
    // This function chunks the plaintext, encrypt the chunks
    // and sends the chunks array to the client
    var tmpPubKey = tmpSocket.cryptweet_user_puk.publicKey;
    // Stringify JSON Object
    var tmpJson = JSON.stringify(json_object);
    // SPLIT stringified JSON INTO CHUNKS OF 70 chars
    // @ ToDo: start with default value and decrease until it works
    // Save max_chunk_size as a socket property
    var arr_chunks = tmpJson.match(/.{1,70}/g);
    var arr_enc_chunks = [];
    var arrayLength = arr_chunks.length;
    for (var i = 0; i < arrayLength; i++) {
        try {
            arr_enc_chunks.push(forge.util.encode64(tmpPubKey.encrypt(arr_chunks[i])));
        } catch (err)
        {
            myLog("sendClient :: There was an error trying to encrypt a chunk of data.\n"
                    + "Error description: " + err.message + "\n");
        }
    }

    if (arr_enc_chunks.length > 0)
    {
        tmpSocket.emit('sendcrypt', {enc_msg_arr: arr_enc_chunks});
    } else {
        myLog("sendClient :: nothing was encrypted, nothing to send !!");
    }
}
function receiveClient(enc_msg_arr) {
    // This functions receives an array of encrypted chunks
    // and tries to decrypt and reconstruct a JSON object
    // it tries three different ways of en-/decoding the decrypted 
    // chunks until it gets a JSON, after that ignores the packet
    if (Object.prototype.toString.call(enc_msg_arr) !== "[object Array]") {
        var tmpstr = enc_msg_arr;
        delete enc_msg_arr;
        enc_msg_arr = [];
        enc_msg_arr[0] = tmpstr;
    }
    var arr_dec_chunks = [];
    var arrayLength = enc_msg_arr.length;
    for (var i = 0; i < arrayLength; i++) {
        // First pass, with base64 decoding
        try
        {
            var decodedChunk = forge.util.decode64(enc_msg_arr[i]);
        }
        catch (err)
        {
            myLog("receiveClient :: first-pass base64 decoding failed\n\n"
                    + "Error description: " + err.message + "\nOriginal chunk: ");
            myLog(enc_msg_arr[i]);
        }
        if (typeof decodedChunk !== "undefined")
        {   // base64 decoding successed 
            // try to decrypt
            myLog("receiveClient :: first-pass: trying to decrypt base64-decoded chunk:");
            try
            {

                var uncrypt_chunk = keypair.privateKey.decrypt(decodedChunk);
            }
            catch (err)
            {
                myLog("receiveClient :: first-pass: There was an error trying to decrypt "
                        + "a chunk of data.\nError description: " + err.message);
            }
            if (typeof uncrypt_chunk === 'undefined')
            {   // First pass failed
                // Second pass, converting hex (from decode64) to bytes
                myLog("receiveClient :: second-pass: trying to decrypt bytes-converted base64-decoded chunk:");
                myLog(decodedChunk);
                try
                {
                    var uncrypt_chunk = keypair.privateKey.decrypt(bytesChunk);
                }
                catch (err)
                {
                    myLog("receiveClient :: second-pass: There was an error trying to decrypt a chunk of data.\n\n"
                            + "Error description: " + err.message + "\n\nDecoded object:");
                }
            }
            delete decodedChunk;
        }
        if (typeof uncrypt_chunk === 'undefined')
        {   // First and second passes failed, trying without base64 decoding
            myLog("receiveClient :: third-pass: trying to decrypt original chunk:");
            try
            {
                myLog(enc_msg_arr[i]);
                var uncrypt_chunk = keypair.privateKey.decrypt(enc_msg_arr[i]);
            }
            catch (err)
            {
                myLog("receiveClient :: third-pass: There was an error trying "
                        + "to decrypt a chunk of data.\nError description: "
                        + err.message);
            }
        }
        if (typeof uncrypt_chunk !== 'undefined')
        {   // At this point we tried everything
            // Add it if we have it, else return false
            arr_dec_chunks.push(uncrypt_chunk);
            delete uncrypt_chunk;
        } else {
            return false;
        }
    }
    var uncrypt = arr_dec_chunks.join('');
    if (typeof uncrypt !== 'undefined' && uncrypt !== false && uncrypt !== null)
    {
        try
        {
            var tmpJson = JSON.parse(uncrypt);
            myLog("receiveClient ::  parsing JSON (second-pass): Parsed JSON:");
            myLog(tmpJson);
            return tmpJson;
        } catch (err) {
            myLog("receiveClient ::  parsing JSON (second-pass): parsing JSON failed."
                    + "Error:\nError description: " + err.message
                    + "\nUncrypted string: " + uncrypt);
        }
        if (typeof tmpJson === 'undefined' || !tmpJson)
        {   // Try to base64decode the decrypted string
            try
            {
                var tmpDecoded = forge.util.decode64(uncrypt);
                myLog("receiveClient :: parsing JSON (second-pass): base64 decoded:\n"
                        + tmpDecoded);
                if (typeof tmpDecoded === "object")
                {
                    if (typeof tmpDecoded.type !== "undefined") {
                        myLog("receiveClient :: parsing JSON (second-pass): "
                                +"we have an object with type property, returning.\n");
                        return tmpDecoded;
                    }
                }
            }
            catch (err)
            {
                myLog("receiveClient :: parsing JSON (second-pass): base64 decoding failed\n"
                        + "Error description: " + err.message + "\nResult: ");
                myLog(tmpDecoded);
            }

            try
            {
                var tmpJson = JSON.parse(tmpDecoded);
                myLog("receiveClient :: parsing JSON (second-pass): Parsed JSON:");
                myLog(tmpJson);
                return tmpJson;
            } catch (err) {
                if (err.message === "Unexpected end of input"){
                 myLog("receiveClient :: parsing JSON (second-pass): invalid JSON. Asking for resend."); 
                 return false;
                }
                myLog("receiveClient :: parsing JSON (second-pass): "
                        + "parsing JSON failed. Error description: "
                        + err.message + "\nWe tried to parse: \n"+ tmpDecoded);
                return false;
            }
        }
    } else {
        return false;
    }
}

function tryClientPuk(puk) {
    try
    {
        var tmpPKI = forge.pki;
        var tmpPubKey =  tmpPKI.publicKeyFromPem(puk);
        var tmpRSAKey = {publicKey: tmpPKI.rsa.setPublicKey( tmpPubKey.n, tmpPubKey.e)};
        return tmpRSAKey;
    } catch (err)
    {
        myLog("There was an error trying to set the "
                + "client's public key.\n\nError description: " + err.message);
        myLog(puk);
        return false;
    }
}

// Start the server
// generate new server key at each session
// DOC ::
// generate an RSA key pair synchronously
//var keypair = pki.rsa.generateKeyPair({bits: 2048, e: 0x10001});
// keypair.privateKey, keypair.publicKey
// encrypt data with a public key (defaults to RSAES PKCS#1 v1.5)
// var encrypted = publicKey.encrypt(bytes);
// decrypt data with a private key (defaults to RSAES PKCS#1 v1.5)
// var decrypted = privateKey.decrypt(encrypted);

/*  For forcing a key from its PEM:
 * var privKey =  pki.privateKeyFromPem("-----BEGIN [...] END PRIVATE KEY-----");
 * var keypair = {privateKey: pki.rsa.setPrivateKey(privKey.n, 
 *    privKey.e, privKey.d, privKey.p, privKey.q, privKey.dP, privKey.dQ, privKey.qInv),
 *    publicKey: pki.rsa.setPublicKey( privKey.n, privKey.e)
 * };
 * 
 */
myLog("Starting RSA key generation");
var pki = forge.pki;
var keypair = pki.rsa.generateKeyPair({bits: 1024, e: 0x10001});

var server_privkey = keypair.privateKey;
var server_pubkey_pem = pki.publicKeyToPem(keypair.publicKey);
myLog("RSA key generation done.");


// Are we ready for encryption ? Alert user accordingly...
if (server_pubkey_pem) {
    welcome_msg = 'Welcome to cryptweet ! Encryption is enabled ;-}<br />Server public key :<br />' + server_pubkey_pem;
} else {
    welcome_msg = 'Welcome to the chat ! Keys are NOT loaded, encryption disabled :´=(';
}

var io = require('socket.io').listen(app.listen(port));
// reduce logging
io.set('log level', 1);



// Define server behaviour
io.sockets.on('connection', function(socket) {
    // On connection, send welcome_msg and pubkey first
    socket.emit('info', {server: true, message: welcome_msg});
    socket.emit('server_rsa_pubkey', {puk: server_pubkey_pem});
    socket.on('sendcrypt', function(data) {
        if (typeof data.enc_msg_arr !== 'undefined' && data.enc_msg_arr !== "")
        {
            try
            {
                var decryptedJson = receiveClient(data.enc_msg_arr);
                myLog("on_sendcrypt :: decrypted message:");
                myLog(decryptedJson);
            } catch (err)
            {
                myLog("There was an error trying to decrypt the received object.\n" + "Error description: "
                        + err.message + "\n");
            }
            if (typeof decryptedJson !== 'undefined') {
                if (typeof decryptedJson.type !== 'undefined'
                        && decryptedJson.type === "client_rsa_puk") {
                    if (typeof decryptedJson.puk !== 'undefined' && decryptedJson.puk !== "") {
                        var tmpRSAKey = tryClientPuk(decryptedJson.puk);
                        if (tmpRSAKey) {
                            socket.cryptweet_user_puk = tmpRSAKey;
                            myLog("New PublicKey received:\n\n" + decryptedJson.puk + "\n\n");
                            sendClient(socket, {type: "message",
                                server: true,
                                message: "I received your PublicKey:\n\n" + decryptedJson.puk});
                        } else {
                            socket.emit('error', {server: true, message: "Error trying to set your public key."});
                        }
                    } else {
                        socket.emit('error', {server: true, message: "Bad Public Key."});
                    }
                } else if (typeof decryptedJson.type !== 'undefined' && decryptedJson.type === "contact_message") {
                    broadcrypt(decryptedJson.message);
                } else if (typeof decryptedJson.type !== 'undefined' && decryptedJson.type === "message") {
                    sendClient(socket, {type: "message", server: true, message: "I received your message:\n\n" + decryptedJson.message});
                } else {
                    if (decryptedJson === false) {
                        if (typeof data.packetId !== "undefined")
                        {
                            myLog("on_sendcrypt :: Sending DECRYPT_FAILED for packet[" + data.packetId + "]");
                            socket.emit('error', {server: true, message: "DECRYPT_FAILED",
                                packetId: data.packetId});
                        } else {
                            myLog("on_sendcrypt :: Sending DECRYPT_FAILED for packet without ID !");
                            socket.emit('error', {server: true,
                                message: "Decryption failed, but packet had no ID !"});
                        }
                    } else {
                        myLog("on_sendcrypt :: Sending UNKN_MSG_TYPE for object :");
                        myLog(decryptedJson);
                        socket.emit('error', {server: true, message: "UNKN_MSG_TYPE",
                            object: data, decrypted: decryptedJson});
                    }
                }
            } else {
                socket.emit('error', {server: true, message: "ERR_CRYPTO_FAILED"});
            }
        } else {
            socket.emit('error', {server: true, message: "Expecting enc_msg_arr in data, but none or an empty array was found."});
        }
        var decryptedJson = null;
    });
});
myLog("Listening on port " + port);



