
/*  To embed a function in a worker, without external file
 * from http://stackoverflow.com/questions/11909934/how-to-pass-functions-to-javascript-web-worker
 * 
 *  function webWorkerWorker() {
 self.postMessage("started1");
 self.onmessage = function(event) {
 ... code ...
 };
 }
 var functionBody = mylib.extractFunctionBody(webWorkerWorker);
 var functionBlob = mylib.createBlob([functionBody]);
 var functionUrl = mylib.createObjectURL(functionBlob);
 */
try {
    importScripts('pidCrypt/pidcrypt.js');
    importScripts('pidCrypt/pidcrypt_util.js');
    importScripts('pidCrypt/asn1.js');
    importScripts('pidCrypt/jsbn.js');
    importScripts('pidCrypt/rng.js');
    importScripts('pidCrypt/prng4.js');
    importScripts('pidCrypt/rsa.js');
} catch (err) {
    throw "Unable to importScripts !"
}


// 
// Functions from 
// https://www.pidder.de/pidcrypt/?page=demo_rsa-encryption

function formatString(str)
{
    var tmp = '';
    for (var i = 0; i < str.length; i += 80)
        tmp += '   ' + str.substr(i, 80) + '\n';
    return tmp;
}

function certParser(cert) {
    var lines = cert.split('\n');
    var read = false;
    var b64 = false;
    var end = false;
    var flag = '';
    var retObj = {};
    retObj.info = '';
    retObj.salt = '';
    retObj.iv;
    retObj.b64 = '';
    retObj.aes = false;
    retObj.mode = '';
    retObj.bits = 0;
    for (var i = 0; i < lines.length; i++) {
        flag = lines[i].substr(0, 9);
        if (i === 1 && flag !== 'Proc-Type' && flag.indexOf('M') === 0)
        {   //unencrypted cert?
            b64 = true;
        }
        switch (flag) {
            case '-----BEGI':
                read = true;
                break;
            case 'Proc-Type':
                if (read)
                    retObj.info = lines[i];
                break;
            case 'DEK-Info:':
                if (read) {
                    var tmp = lines[i].split(',');
                    var dek = tmp[0].split(': ');
                    var aes = dek[1].split('-');
                    retObj.aes = (aes[0] === 'AES') ? true : false;
                    retObj.mode = aes[2];
                    retObj.bits = parseInt(aes[1]);
                    retObj.salt = tmp[1].substr(0, 16);
                    retObj.iv = tmp[1];
                }
                break;
            case '':
                if (read)
                    b64 = true;
                break;
            case '-----END P':
                if (read) {
                    b64 = false;
                    read = false;
                }
                break;
            default:
                if (read && b64)
                    retObj.b64 += pidCryptUtil.stripLineFeeds(lines[i]);
        }
    }
    return retObj;
}
// end functions from pidCrypt

function tryRSAdecrypt(rsa, encrypted) {
    var success = false;
    var firstPass = false;
    var secPass = false;
    var thirdPass = false;
    while (!success)
    {
        if (firstPass && secPass)
        {
            break;
        } else if (firstPass)
        {   // 1st pass done, now second pass 
            //  try without decodeBase64 before decrypt
            secPass = true;
            //encrypted = pidCryptUtil.decodeBase64(origEncrypted);
            //encrypted = pidCryptUtil.decodeBase64(encrypted);
            try
            {
                var decrypted = rsa.decryptRaw(encrypted);
                success = (decrypted && decrypted !== null && decrypted.length > 0) ? true : false;
                this.postMessage({cmd: "put_console_log",
                    object: ":: cryptoWorker :: tryRSAdecrypt :: second-pass: SUCCESS (decodeBase64): " 
                            + decrypted});
            }
            catch (err)
            {
                success = false;
                var err_txt = ":: cryptoWorker :: tryRSAdecrypt :: second-pass: failed to decrypt a chunk of data.\n\n";
                err_txt += ":: cryptoWorker :: tryRSAdecrypt :: second-pass: Error description: "
                        + err.message + "\n\n" + err.trace + "\n\n";
                this.postMessage({cmd: "put_console_log",
                    object: err_txt});
            }
        } else { // it is 1st pass, set flag true
            firstPass = true;
            // 1st pass: try to decodeBase64 before decrypt
            try
            {
                var dec64 = pidCryptUtil.decodeBase64(encrypted);
                var tmpHex = pidCryptUtil.convertToHex(dec64);
                var decrypted = rsa.decryptRaw(tmpHex);
                success = (decrypted && decrypted !== null && decrypted.length > 0) ? true : false;
                this.postMessage({cmd: "put_console_log",
                    object: ":: cryptoWorker :: tryRSAdecrypt :: first-pass: SUCCESS: " + decrypted});
            }
            catch (err)
            {
                success = false;
                var err_txt = ":: cryptoWorker :: tryRSAdecrypt :: first-pass: failed to decrypt a chunk of data.\n\n";
                err_txt += ":: cryptoWorker :: tryRSAdecrypt :: first-pass: Error description: "
                        + err.message + "\n\n";
                this.postMessage({cmd: "put_console_log",
                    object: JSON.stringify(err)});
            }
        }
    }
    if (typeof decrypted !== "undefined")
    {
        return decrypted;
    } else {
        return false;
    }
}
function decryptArray(tmpCrypto, enc_msg_arr)
{   /* @ToDo: 
    // Check if this is stringified JSON or base64 encoded
            var isJson = (uncrypt_chunk[0] === "{") ? true : false;
            if (isJson)
            {
                arr_dec_chunks.push(uncrypt_chunk);
            } else {
                try
                {
                    var tmpDecodedChunk = forge.util.decode64(uncrypt_chunk);
                    //console.log(":: receiveClient ::  Parsed JSON");
                    arr_dec_chunks.push(tmpDecodedChunk);

                } catch (err) {
                    console.log(new Date().toISOString() + " :: receiveClient :: first-pass: parsing JSON failed."
                            +"Error:\nError description: " + err.message + "\nUncrypted string :" + uncrypt);
                }
            }
    */
    
    var arr_dec_chunks = [];
    var arrayLength = enc_msg_arr.length;
    for (var i = 0; i < arrayLength; i++) {
        try
        {
            var uncrypt_chunk = tryRSAdecrypt(tmpCrypto, enc_msg_arr[i]);
        }
        catch (err)
        {
            var err_txt = ":: cryptoWorker :: decryptArray :: There was an error trying to decrypt a chunk of data.\n\n";
            err_txt += ":: cryptoWorker :: decryptArray :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
            this.postMessage({cmd: "put_console_log",
                object: err_txt});
        }
        if (typeof uncrypt_chunk !== 'undefined' && uncrypt_chunk)
        {
            arr_dec_chunks.push(uncrypt_chunk);
        } else {
            // If we can't decrypt the first chunk then 
            // no need to try further
            return false;
        }
    }
    if (arr_dec_chunks.length > 0)
    {
        return arr_dec_chunks;
    } else {
        return false;
    }
}



// Setup an event listener that will handle messages sent to the worker.
self.addEventListener('message', function(e) {
    //throw "cryptoWorker :: received message.";
    //throw JSON.stringify(e.data);
    //throw e.data;
    var data = e.data;
    if (typeof data !== "undefined" && typeof data.cmd !== "undefined")
    {
        switch (data.cmd) {
            case 'encryptJsonRSA':
                if (typeof data.plaintext !== "undefined" && typeof data.puk !== "undefined")
                {
                    var params = certParser(data.puk.trim());
                    //this.postMessage({cmd: "put_console_log", object: JSON.stringify(params)});
                    if (params.b64)
                    {
                        var key = pidCryptUtil.decodeBase64(params.b64);
                    }
                    try {
                        //new RSA instance
                        var rsa = new pidCrypt.RSA();
                        //this.postMessage({cmd: "put_console_log", object: JSON.stringify(rsa)});
                        //RSA encryption
                        //ASN1 parsing
                        var asn = pidCrypt.ASN1.decode(
                                pidCryptUtil.toByteArray(key));
                        //this.postMessage({cmd: "put_console_log", object: JSON.stringify(asn)});
                        var tree = asn.toHexTree();
                        //this.postMessage({cmd: "put_console_log", object: JSON.stringify(tree)});

                        //setting the public key for encryption
                        rsa.setPublicKeyFromASN(tree);

                        // SPLIT stringified JSON INTO CHUNKS OF 70 chars (UTF8 ?)
                        // @TODO: try with default size and decrease
                        // until finding a size that works, then 
                        // store this max_chunk_size in Contact's crypto
                        var chunkSize = 70;
                        var chunkRegEx = new RegExp(".{1," + chunkSize + "}", "g");
                        var arr_chunks = data.plaintext.match(chunkRegEx);
                        var arr_enc_chunks = [];
                        var arrayLength = arr_chunks.length;
                        for (var i = 0; i < arrayLength; i++) {
                            var tmpEncChunk = rsa.encrypt(arr_chunks[i]);
                            this.postMessage({cmd: "put_console_log", object: tmpEncChunk});
                            var tmpHex = pidCryptUtil.convertFromHex(tmpEncChunk);
                            var tmp64 = pidCryptUtil.encodeBase64(tmpHex);
                            arr_enc_chunks.push(tmp64);
                        }
                    } catch (err) {
                        this.postMessage({cmd: "put_console_log", object: JSON.stringify(err)});
                    }
                    //var tmpHex = pidCryptUtil.formatHex(encrypted, 63);
                    //var tmpB64 = pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(tmpHex));
                    // var result =  pidCryptUtil.fragment(tmpB64);
                    //var breakpoint = true;
                    if (typeof arr_enc_chunks !== "undefined")
                    {
                        this.postMessage({
                            cmd: "put_encrypted",
                            encrypted: arr_enc_chunks
                        });
                    }
                }
                this.close();
                break;
            case 'receiveRSAEncrypted':
                if (typeof data.encrypted !== "undefined" && typeof data.prk !== "undefined")
                {
                    params = certParser(data.prk.trim());
                    if (params.b64) {
                        var key = pidCryptUtil.decodeBase64(params.b64);
                        var rsa = new pidCrypt.RSA();
                        //RSA decryption
                        //ASN1 parsing
                        var asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(key));
                        var tree = asn.toHexTree();
                        //alert(showData(tree));
                        //setting the private key for encryption
                        rsa.setPrivateKeyFromASN(tree);



                        if (Object.prototype.toString.call(data.encrypted)
                                === '[object Array]')
                        {   // We are passed an array of encrypted chunks
                            this.postMessage({
                                cmd: "put_console_log",
                                object: ":: cryptoWorker :: decrypt :: We received an array"
                            });
                            var firstPass = decryptArray(rsa, data.encrypted);
                            if (firstPass)
                            {
                                try {
                                    var tmpJson = JSON.parse(firstPass.join(''));
                                } catch (err) {
                                    var err_txt = ":: cryptoWorker :: decrypt :: There was an error trying to parse stringified JSON.\n\n";
                                    err_txt += ":: cryptoWorker :: decrypt :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                                    this.postMessage({cmd: "put_console_log", object: err_txt});
                                }

                                if (typeof tmpJson !== 'undefined'
                                        && Object.prototype.toString.call(tmpJson) === '[object Array]')
                                {   // This is mostly the case when receiving double encrypted messages
                                    // Try to decrypt again
                                    var secondPass = decryptArray(rsa, tmpJson);
                                    if (secondPass)
                                    {
                                        this.postMessage({
                                            cmd: "put_console_log",
                                            object: ":: cryptoWorker :: decrypt :: second-pass decryption\n"});
                                        try {
                                            var newTmpJson = JSON.parse(secondPass.join(''));
                                        } catch (err) {
                                            var err_txt = ":: cryptoWorker :: decrypt :: There was an error trying to parse stringified JSON.\n\n";
                                            err_txt += ":: cryptoWorker :: decrypt :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                                            this.postMessage({cmd: "put_console_log", object: err_txt});

                                        }
                                if (typeof newTmpJson === 'undefined')
                                {   // try to decodeBase64 each chunk
                                    var decodedArray=[];
                                    
                                    for (var i = 0; i < secondPass.length; i++)
                                    {
                                        decodedArray.push(pidCryptUtil.decodeBase64(secondPass[i]));
                                        this.postMessage({cmd: "put_console_log", object: decodedArray});
                                    }
                                    try {
                                        var newTmpJson = JSON.parse(decodedArray.join(''));
                                    } catch (err) {
                                        var err_txt = ":: cryptoWorker :: decrypt :: There was an error trying to parse stringified JSON.\n\n";
                                        err_txt += ":: cryptoWorker :: decrypt :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                                        this.postMessage({cmd: "put_console_log", object: JSON.stringify(err)});
                                    }
                                }
                                if (typeof newTmpJson !== 'undefined'
                                                && (Object.prototype.toString.call(newTmpJson) === "[object Object]"))
                                        {   // first-pass worked, process JSON
                                            this.postMessage({cmd: "put_decrypted", decrypted: JSON.stringify(newTmpJson)});
                                        } else {
                                            // This time it means the message is not for us
                                            err_txt = ":: cryptoWorker :: decrypt :: Unable to decrypt data, this goes to /dev/null ;-}";
                                            this.postMessage({cmd: "put_console_log", object: err_txt});
                                            this.close();
                                        }
                                    } else {
                                        err_txt = ":: cryptoWorker :: decrypt :: Unable to decrypt data, this goes to /dev/null ;-}";
                                        this.postMessage({cmd: "put_console_log", object: err_txt});
                                        this.close();
                                    }
                                } else if (Object.prototype.toString.call(tmpJson) === "[object Object]") {
                                    // first-pass worked, return JSON
                                    this.postMessage({cmd: "put_decrypted",
                                        decrypted: JSON.stringify(tmpJson)});
                                }
                            } else {
                                err_txt = ":: cryptoWorker :: decrypt :: Unable to decrypt data, this goes to /dev/null ;-}";
                                this.postMessage({cmd: "put_console_log", object: err_txt});
                            }
                        } else {
                            var decrypted = tryRSAdecrypt(rsa, data.encrypted);
                            try {
                                var tmpJson = JSON.parse(decrypted.join(''));
                            } catch (err) {

                                var err_txt = ":: cryptoWorker :: decrypt :: There was an error trying to parse stringified JSON.\n\n";
                                err_txt += ":: cryptoWorker :: decrypt :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                                this.postMessage({cmd: "put_console_log", object: err_txt});

                            }
                            if (typeof tmpJson !== "undefined")
                            {
                                this.postMessage({cmd: "put_decrypted", decrypted: JSON.stringify(tmpJson)});
                            } else {
                                this.postMessage({cmd: "put_decrypted", decrypted: decrypted});

                            }
                            this.close();

                        }
                        break;
                    }
                }
        }
    }
}, false);
