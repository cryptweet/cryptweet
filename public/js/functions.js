/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


/* COMMON FUNCTIONS */
function uniqueId() {
// Math.random should be unique because of its seeding algorithm.
// Convert it to base 36 (numbers + letters), and grab the first 9 characters
// after the decimal.
    return '_' + Math.random().toString(36).substr(2, 9);
}


function count_obj(obj) {
    var i = 0;
    for (var key in obj) {
        ++i;
    }

    return i;
}

function myLength(obj) {
    if (typeof Object.keys !== "undefined")
    {
        return Object.keys(obj).length;
    } else {
        // browser doesn't support it, iterate and count
        var count = 0;
        var i;

        for (i in obj) {
            if (obj.hasOwnProperty(i)) {
                count++;
            }
        }
    }
}

function isEmpty(obj) {
    // from http://stackoverflow.com/questions/4994201/is-object-empty
    // null and undefined are "empty"
    if (obj === null)
        return true;

    // Assume if it has a length property with a non-zero value
    // that that property is correct.
    if (obj.length > 0)
        return false;
    if (obj.length === 0)
        return true;

    // Otherwise, does it have any properties of its own?
    // Note that this doesn't handle
    // toString and valueOf enumeration bugs in IE < 9
    for (var key in obj) {
        if (hasOwnProperty.call(obj, key))
            return false;
    }
    return true;
}

// Focus state of window
function onBlur() {
    FOCUS = false;
}

function onFocus() {
    FOCUS = true;
}




/* CRYPTO FUNCTIONS */
function loadMyKeys() {
    var my_pubkey = $("#my_pubkey");
    var my_privkey = $("#private_key");

    if (my_privkey[0].value !== "" && srv_crypto)
    {   // reset my crypto
        my_crypto = load_keys(null, my_privkey.val());
        if (decrypt(my_crypto, encrypt(my_crypto, "TEST")) === "TEST")
        { // Private key is valid, send our public key to the server
            my_pubkey.val(my_crypto.getPublicKey());
            var sendPukJson = {type: "client_rsa_puk", puk: my_crypto.getPublicKey()};
            // Generate uniqueId for this packet
            var packetId = uniqueId();
            // Store json for re-sending if server decyption fails
            sent_packets[packetId] = sendPukJson;
            sent_packets[packetId].resend = "server";
            // Encrypt and send
            if (typeof Worker !== "undefined" && ENABLE_WORKERS)
            {
                encryptJsonThreaded(srv_crypto, sendPukJson, packetId, false);
            } else {
                sendEncrypted(socket, encryptJson(srv_crypto, sendPukJson), packetId);
            }
        } else {
            alert("Problem with your private key: encryption/decryption test failed !");
        }
    }
}
function load_keys(puk, prk) {
    var tmpCrypto = new JSEncrypt();
    if (typeof puk !== "undefined" && puk)
    {
        tmpCrypto.setPublicKey(puk);
    }
    if (typeof prk !== "undefined" && prk)
    {
        tmpCrypto.setPrivateKey(prk);
    }
    if (tmpCrypto.key)
    {
        return tmpCrypto;
    } else {
        alert("Something is wrong with your keys, unable to build Crypto !  ");
    }
}
function genMyKeys() {
    var my_privkey = $("#private_key");
    var my_pubkey = $("#my_pubkey");
    my_crypto = new JSEncrypt({defaultKeySize: 4096});
    if (srv_crypto)
    {
        my_privkey.val('');
        var GenKeyLoading = setInterval(function() {
            my_privkey.val(my_privkey.val() + '=x*x=');
        }, 500);
        my_crypto.getKey(function() {
            clearInterval(GenKeyLoading);
            if (decrypt(my_crypto, encrypt(my_crypto, "TEST")) === "TEST")
            { // Private key is valid, send our public key to the server
                //my_privkey.val(my_crypto.getPrivateKey().replace(/\n/g, "\r\n"));
                //my_pubkey.val(my_crypto.getPublicKey().replace(/\n/g, "\r\n"));
                my_privkey.val(my_crypto.getPrivateKey());
                my_pubkey.val(my_crypto.getPublicKey());
                loadMyKeys();
            } else {
                alert("Problem with the generated keys: encryption/decryption test failed !");
            }
        });
    } else {
        alert(":: genMyKeys :: Server Crypto not loaded, try again in a few seconds "
                + "or reload the page if it persists.");
    }
}


function filterHtml(str)
{
    /* Found on http://www.uize.com/appendixes/javascript-optimization.html
     * @ToDo: this function should escape any html char, so that it never outputs
     * something interpretable by the browser, but still don't loose chars if
     * the users want to exchange html or javascript code
     _htmlAsIs =
     '<pre>' +
     _html
     .replace (/\t/g,'  ')   // turn tabs into three spaces
     .replace (/&/g,'&amp;') // entitize "&" (to kill entities)
     .replace (/</g,'&lt;')  // entitize "<" (to kill HTML tags)
     .replace (/>/g,'&gt;')  // entitize ">" (it's the right thing)
     + '</pre>'
     ;
     */
    str = str.replace(/<\s*br\/*>/gi, "\n");
    str = str.replace(/<\s*a.*href="(.*?)".*>(.*?)<\/a>/gi, " $2 (Link->$1) ");
    str = str.replace(/<\s*\/*.+?>/ig, "\n");
    str = str.replace(/ {2,}/gi, " ");
    str = str.replace(/\n+\s*/gi, "\n\n");
    return str;
}
function process_data(tmpCrypto, data) {
    var testdecrypt = decrypt(tmpCrypto, data.enc_msg);
    if (testdecrypt) { // Message was crypted, else null
        data.message = decrypt(testdecrypt); // restore uncrypted
    }
    return data;
}
// FUNCTIONS COPIED IN WORKER
// We keep them here for non-worker browser compatibility
function encrypt(tmpCrypto, uncrypted)
{
    if (tmpCrypto)
    {
        return tmpCrypto.encrypt(uncrypted);
    }
}

function decrypt(tmpCrypto, crypted)
{
    if (tmpCrypto)
    {
        return tmpCrypto.decrypt(crypted);
    }
}

function decryptThreaded(tmpCrypto, encrypted)
{
    if (tmpCrypto)
    {
        var worker = new Worker('js/crypto-worker.js');
        worker.addEventListener('message', function(e) {
            var data = e.data;
            switch (data.cmd) {
                case 'put_decrypted':
                    try {
                        var tmpJson = JSON.parse(data.decrypted);
                    } catch (err) {
                        if (DEBUG >= 1) {
                            var err_txt = ":: decryptThreaded :: There was an error trying parse stringified JSON.\n\n";
                            err_txt += ":: decryptThreaded :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                            console.log(err_txt);
                        }
                    }
                    if (Object.prototype.toString.call(tmpJson) === "[object Object]")
                    {
                        console.log(":: decryptThreaded :: Worker decrypted object");
                        console.log(tmpJson);
                        processJson(tmpJson);
                    }
                    worker.terminate();
                    break;
                case 'put_console_log':
                    logWorker(data.object);
                    break;
            }
        }, false);

        worker.postMessage({
            cmd: 'receiveRSAEncrypted',
            prk: tmpCrypto.getPrivateKey(),
            encrypted: encrypted
        });
    }
}

function encryptJson(tmpCrypto, json_object) {
    var tmpJson = JSON.stringify(json_object);
    if (DEBUG >= 3) {
        console.log("sendEncrypted :: stringified JSON : ");
        console.log(tmpJson);
    }

    // SPLIT stringified JSON INTO CHUNKS OF 70 chars (UTF8 ?)
    // @TODO: try with default size and decrease
    // until finding a size that works, then 
    // store this max_chunk_size in Contact's crypto
    var arr_chunks = tmpJson.match(/.{1,70}/g);
    if (DEBUG >= 3) {
        console.log("sendEncrypted :: chunks array : ");
        console.log(arr_chunks);
    }
    var arr_enc_chunks = [];
    var arrayLength = arr_chunks.length;
    for (var i = 0; i < arrayLength; i++) {
        var tmpEncChunk = encrypt(tmpCrypto, pidCryptUtil.encodeBase64(arr_chunks[i]));

        if (DEBUG >= 3) {
            console.log("sendEncrypted :: encrypting chunk #" + i + ": ");
            console.log(arr_chunks[i]);
            console.log(tmpEncChunk);
        }
        arr_enc_chunks.push(tmpEncChunk);
    }
    return arr_enc_chunks;
}

function encryptJsonThreaded(tmpCrypto, json_object, packetId, sendContact) {
    // Send contact flag is true by default
    // We rarely send something to the server itself
    if (typeof sendContact === "undefined") {
        sendContact = true;
    }
    var stringJson = JSON.stringify(json_object);
    if (DEBUG >= 3) {
        console.log(":: encryptJsonThreaded :: Entering. Got object:");
        console.log(stringJson);
    }
    if (sendContact) {
        /* Crypto Worker to do the job in background */
        var contactWorker = new Worker('js/crypto-worker.js');
        // Listen for event messages passed back from the worker
        contactWorker.addEventListener('message', function(e) {
            var data = e.data;
            switch (data.cmd) {
                case 'put_encrypted':
                    // Encryption for contact done, encapsulate in server's crypto
                    logWorker("eventListener put_encrypted, entering. Got data :");
                    logWorker(data);
                    sent_packets[packetId] = data;
                    sent_packets.resend = "contact";
                    /* Crypto Worker to do the job in background */
                    var serverWorker = new Worker('js/crypto-worker.js');
                    // Listen for event messages passed back from the worker
                    serverWorker.addEventListener('message', function(e) {
                        var data = e.data;
                        switch (data.cmd) {
                            case 'put_encrypted':
                                if (DEBUG >= 3) {
                                    console.log(":: encryptJsonThreaded :: encoded for server:");
                                    console.log(data.encrypted);
                                }
                                // Encryption for server done, send
                                sendEncrypted(socket, data.encrypted, packetId);
                                break;
                            case 'put_console_log':
                                logWorker(data.object);
                                break;
                        }
                    }, false);
                    serverWorker.postMessage({
                        cmd: "encryptJsonRSA",
                        puk: srv_crypto.getPublicKey(),
                        plaintext: JSON.stringify({
                            type: "contact_message",
                            message: data.encrypted
                        })
                    });
                    break;
                case 'put_console_log':
                    logWorker(data.object);
                    break;
            }
        }, false);

        contactWorker.postMessage({
            cmd: "encryptJsonRSA",
            puk: tmpCrypto.getPublicKey(),
            plaintext: stringJson
        });
    } else {
        // Store josn for resending
        sent_packets[packetId] = json_object;
        sent_packets.resend = "server";
        var serverWorker = new Worker('js/crypto-worker.js');
        // Listen for event messages passed back from the worker
        serverWorker.addEventListener('message', function(e) {
            var data = e.data;
            switch (data.cmd) {
                case 'put_encrypted':
                    if (DEBUG >= 3) {
                        console.log(":: encryptJsonThreaded :: encoded for server:");
                    }
                    console.log(data.encrypted);
                    // Encryption for server done, send
                    sendEncrypted(socket, data.encrypted, packetId);
                    break;
                case 'put_console_log':
                    logWorker(data.object);
                    break;
            }
        }, false);
        serverWorker.postMessage({
            cmd: "encryptJsonRSA",
            puk: srv_crypto.getPublicKey(),
            plaintext: JSON.stringify(json_object)
        });
    }

}

function logWorker(logObj) {
    if (DEBUG >= 3) {
        if (typeof logObj === "string")
        {
            try {
                var parsedJson = JSON.parse(logObj);
            } catch (err) {
                // this is not a json, just log the string
                console.log(":: logWorker :: got a string : " + logObj);
            }
            if (typeof parsedJson === "object")
            {
                console.log(":: logWorker :: got JSON :");
                console.log(parsedJson);
            }
        } else if (typeof logObj === "object")
        {    // this is an object, just log the object
            console.log(":: logWorker :: got Object : ");
            console.log(logObj);
        } else {
            // just log it
            console.log(":: logWorker :: got unknown type : ");
            console.log(logObj);
        }
    }
}

function tryRSAdecrypt(rsa, encrypted) {
    // @ToDo: move to CryptweetUtil file so that we 
    // can call the function form main-script and
    // from Worker
    var success = false;
    var firstPass = false;
    var secPass = false;
    var thirdPass = false;
    if (DEBUG >= 3) {
        console.log(":: tryRSAdecrypt :: entering. Encrypted chunk:");
        console.log(encrypted);
    }
    while (!success)
    {
        if (firstPass && secPass && thirdPass)
        {
            break;
        } else if (firstPass && secPass)
        {   // 2nd pass done, now third pass 
            //  try to decodeBase64  without converting to hex
            //  before decrypt
            thirdPass = true;
            try
            {   // If we receive raw bytes, try to convert to Base64 for JSencrypt
                var decrypted = rsa.decrypt(pidCryptUtil.encodeBase64(encrypted));
                success = (decrypted && decrypted.length > 0) ? true : false;
                if (DEBUG >= 3) {
                    console.log(":: tryRSAdecrypt :: third-pass: SUCCESS (convertToHex)");
                    console.log(decrypted);
                }
            }
            catch (err)
            {
                success = false;
                if (DEBUG >= 3) {
                    var err_txt = ":: tryRSAdecrypt :: third-pass: failed to decrypt a chunk of data.\n\n";
                    err_txt += ":: tryRSAdecrypt :: third-pass: Error description: "
                            + err.message + "\n\n" + err.trace + "\n\n";
                    console.log(err_txt);
                }
            }

        } else if (firstPass)
        {   // 1st pass done, now second pass 
            //  try to decodeBase64 after converting to Hex
            //  before decrypt
            secPass = true;
            try
            {
                decrypted = rsa.decrypt(
                        pidCryptUtil.encodeBase64(
                                pidCryptUtil.convertToHex(encrypted))
                        );
                success = (decrypted && decrypted.length > 0) ? true : false;
                if (success)
                {
                    if (DEBUG >= 3) {
                        console.log(":: tryRSAdecrypt :: second-pass: SUCCESS (convertToHex)");
                        console.log(decrypted);
                    }
                } else {
                    return false;
                }
            }
            catch (err)
            {
                success = false;
                if (DEBUG >= 3) {
                    var err_txt = ":: tryRSAdecrypt :: second-pass: failed to decrypt a chunk of data.\n\n";
                    err_txt += ":: tryRSAdecrypt :: second-pass: Error description: "
                            + err.message + "\n\n" + err.trace + "\n\n";
                    console.log(err_txt);
                }
            }
        } else { // it is 1st pass, set flag true
            firstPass = true;

            try
            {
                var decrypted = rsa.decrypt(encrypted);
                success = (decrypted && decrypted.length > 0) ? true : false;
                if (success)
                {
                    if (DEBUG >= 3) {
                        console.log(":: tryRSAdecrypt :: first-pass: SUCCESS (encodeBase64) ");
                        console.log(decrypted);
                    }
                }
            }
            catch (err)
            {
                success = false;
                if (DEBUG >= 3) {
                    var err_txt = ":: tryRSAdecrypt :: first-pass: failed to decrypt a chunk of data.\n\n";
                    err_txt += ":: tryRSAdecrypt :: first-pass: Error description: "
                            + err.message + "\n\n" + err.trace + "\n\n";
                    console.log(err_txt);
                }
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
{   // @ToDo: move to CryptweetUtil file so that we 
    // can call the function form main-script and
    // from Worker
    var arr_dec_chunks = [];
    var arrayLength = enc_msg_arr.length;
    for (var i = 0; i < arrayLength; i++) {
        try
        {
            var uncrypt_chunk = tryRSAdecrypt(tmpCrypto, enc_msg_arr[i]);
        }
        catch (err)
        {
            if (DEBUG >= 3) {
                var err_txt = ":: decryptArray :: There was an error trying to decrypt a chunk of data.\n\n";
                err_txt += ":: decryptArray :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                console.log(err_txt);
            }
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

function receiveEncrypted(tmpCrypto, enc_msg_arr) {
    if (DEBUG >= 3) {
        console.log(":: receiveEncrypted :: got : ");
        console.log(enc_msg_arr);
    }
    if (typeof Worker !== "undefined" && ENABLE_WORKERS)
    {
        decryptThreaded(tmpCrypto, enc_msg_arr);
    } else {
        var firstPass = decryptArray(tmpCrypto, enc_msg_arr);
        if (firstPass)
        {
            try {
                var tmpJson = JSON.parse(firstPass.join(''));
            } catch (err) {
                if (DEBUG >= 3) {
                    var err_txt = ":: receiveEncrypted :: There was an error trying to parse stringified JSON.\n\n";
                    err_txt += ":: receiveEncrypted :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                    console.log(err_txt);
                }
            }
            if (typeof tmpJson !== 'undefined'
                    && Object.prototype.toString.call(tmpJson) === '[object Array]')
            {   // This is mostly the case when receiving double encrypted messages
                // Try to decrypt again
                var secondPass = decryptArray(tmpCrypto, tmpJson);
                if (secondPass)
                {
                    if (DEBUG >= 3) {
                        console.log(":: receiveEncrypted :: second-pass decrypted data:\n");
                        console.log(secondPass);
                    }
                    try {
                        var newTmpJson = JSON.parse(secondPass.join(''));
                    } catch (err) {
                        if (DEBUG >= 1) {
                            var err_txt = ":: receiveEncrypted :: There was an error trying to parse stringified JSON.\n\n";
                            err_txt += ":: receiveEncrypted :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                            console.log(err_txt);
                        }
                    }
                    if (typeof newTmpJson !== 'undefined'
                            && (Object.prototype.toString.call(newTmpJson) === "[object Object]"))
                    {   // second-pass worked, process JSON
                        if (DEBUG >= 3) {
                            console.log(newTmpJson);
                        }
                        processJson(newTmpJson);
                    } else {
                        // Try again with decodeBase64
                        if (DEBUG >= 3) {
                            console.log(":: receiveEncrypted :: second-pass: failed to parse JSON :");
                            console.log(newTmpJson);
                            console.log(":: receiveEncrypted :: second-pass: try again with base64 decoding:");
                        }
                        try {
                            var newTmpJson = JSON.parse(pidCryptUtil.decodeBase64(secondPass.join('')));
                            processJson(newTmpJson);
                        } catch (err) {
                            if (DEBUG >= 1) {
                                var err_txt = ":: receiveEncrypted :: nothing gave us JSON. Giving up.\n\n";
                                err_txt += ":: receiveEncrypted :: Error description: " + err.message + "\n\n" + err.trace + "\n\n";
                                console.log(err_txt);
                            }
                            return false;
                        }
                    }
                } else {
                    if (DEBUG >= 3) {

                        console.log(":: receiveEncrypted :: first-pass: failed to parse JSON :");
                        console.log(tmpJson);
                    }
                    return false;
                }
            } else if (Object.prototype.toString.call(tmpJson) === "[object Object]") {
                // first-pass worked, process JSON
                if (DEBUG >= 3) {
                    console.log(tmpJson);
                }
                processJson(tmpJson);
            } else {
                if (DEBUG >= 3) {
                    console.log(":: receiveEncrypted :: fist-pass failed, non need to try further");
                }
                return false;
            }
        } else {
            if (DEBUG >= 3) {
                console.log(":: receiveEncrypted :: fist-pass failed, non need to try further");
            }
            return false;
        }
    }
}
// END CRYPTO FUNCTIONS

/* USER INTERFACE FUNCTIONS */
function addTab(conv) {
    var tabs = $("#tabs").tabs();
    var tabexists = tabs.find("#" + conv.id);
    if (tabexists.length > 0)
    {
        refresh_conversation(conv);
        return false;
    } else {
        var ul = tabs.find("ul");
        $('<li><a href="#' + conv.id + '" id="' + conv.id + '_tabLink">New Talk</a></li>').appendTo(ul);
        // Create Conv Div
        var convDiv = $('<div id="' + conv.id + '"></div>');
        // Add controls Div
        $('<div class="controls"></div>').appendTo(convDiv);
        var controlsDiv = convDiv.find(".controls");
        // Add nickname to controls
        $('<span>Talk as </span>').appendTo(controlsDiv);
        $('<input class="nickname" id="' + conv.controls.nickname + '">').appendTo(controlsDiv);
        $('<br />').appendTo(controlsDiv);
        // Add message queue div
        $('<div class="conversation" id="' + conv.controls.messages + '"></div>').appendTo(controlsDiv);
        // Add user message input, with eventListener for Enter key
        $('<textarea class="user-message" id="' + conv.controls.userMessage
                + '"></textarea>').appendTo(controlsDiv);
        // Add Send Button, with eventListener for Click
        $('<input type="button" value="send" id="'
                + conv.controls.btSend + '">').appendTo(controlsDiv);
        $('<br />').appendTo(controlsDiv);
        // Add contacts div
        $('<span>Contacts in this conversation: </span>').appendTo(controlsDiv);
        $('<div class="contacts" id="' + conv.controls.contacts + '"></div>').appendTo(controlsDiv);
        $("<span>Contact's pubkey </span>").appendTo(controlsDiv);
        $('<br />').appendTo(controlsDiv);
        // Add contact's pubkey box
        $('<textarea class="keybox" id="' + conv.controls.contactPuk + '"></textarea>').appendTo(controlsDiv);
        // Add invite button
        $('<input type="button" value="Invite contact" id="' + conv.controls.btInvite + '"><br>').appendTo(controlsDiv);
        $('<br />').appendTo(controlsDiv);
        $('<span>Your public key in this conversation :</span>').appendTo(controlsDiv);
        $('<textarea class="keybox" id="' + conv.controls.myPuk + '"></textarea>').appendTo(controlsDiv);
        $('<br />').appendTo(controlsDiv);

        var arrSoundSelect = [
            {val: "beer_can_opening", text: ' beer can opening '},
            {val: "bell_ring", text: ' bell ring '},
            {val: "branch_break", text: ' branch break '},
            {val: 'button_click', text: ' button click '},
            {val: 'button_click_on', text: ' button click on '},
            {val: 'button_push', text: ' button push '},
            {val: 'button_tiny', text: ' button tiny '},
            {val: 'camera_flashing', text: ' camera flashing '},
            {val: 'camera_flashing_2', text: ' camera flashing 2'},
            {val: 'cd_tray', text: ' cd tray '},
            {val: 'computer_error', text: ' computer error '},
            {val: 'door_bell', text: ' door bell '},
            {val: 'door_bump', text: ' door bump '},
            {val: 'glass', text: ' glass '},
            {val: 'keyboard_desk', text: ' keyboard desk '},
            {val: 'light_bulb_breaking', text: ' light bulb breaking '},
            {val: 'metal_plate', text: ' metal plate '},
            {val: 'metal_plate_2', text: ' metal plate 2'},
            {val: 'pop_cork', text: ' pop cork '},
            {val: 'snap', text: ' snap '},
            {val: 'staple_gun', text: ' staple gun '},
            {val: 'tap', text: ' tap '},
            {val: 'water_droplet', text: ' water droplet 1 '},
            {val: 'water_droplet_2', text: ' water droplet 2 '},
            {val: 'water_droplet_3', text: ' water droplet 3 '}
        ];
        var sel = $('<select id="' + conv.controls.soundSelector + '">').appendTo(controlsDiv);
        $(arrSoundSelect).each(function() {
            sel.append($("<option>").attr('value', this.val).text(this.text));
        });

        convDiv.appendTo(tabs);
        // Event Listeners
        $('#' + conv.id).on('keypress', '#' + conv.controls.userMessage, function(e) {
            if (e.which === 13) {
                sendMessage(conv.id);
            }
        });
        $('#' + conv.id).on('click', '#' + conv.controls.btSend, function(e) {
            sendMessage(conv.id);
        });
        $('#' + conv.id).on('click', '#' + conv.controls.btInvite, function(e) {
            conv.inviteContact($('#' + conv.controls.contactPuk).val());
        });
        $('#' + conv.id).on('change', '#' + conv.controls.nickname, function(e) {
            conv.previousNick = conv.nickname;
            conv.nickname = $('#' + conv.controls.nickname).val();
            var tmpTxt = '<i>' + conv.previousNick + '</i> changed his/her nickname to '
                    + '<b>' + conv.nickname + '</b>...';
            //var newLength = conv.myMessages.push(tmpTxt);
            conv.broadcastRSA({type: "contact_message",
                myTime: $.now(), msgId: "-1",
                message: tmpTxt, system: true
            });
        });
        $('#' + conv.id).on('change', '#' + conv.controls.soundSelector, function(e) {
            conv.notifSound = $(this).val();
        });

        // Colors

        $('#' + conv.controls.messages).css('border', '5px solid red');
        refresh_conversation(conv);
        return true;
    }
}

function delTab(tabId) {
    var tabs = $("#tabs").tabs();
    tabs.tabs("refresh");
}

function refresh_conversation(conv) {
    if (typeof conv !== 'undefined' && !isEmpty(conv))
    {
        var tabs = $("#tabs").tabs();
        $('#' + conv.id + "_tabLink").html(conv.contacts[conv.firstContact].nickname);
        $('#' + conv.controls.nickname).val(conv.nickname);
        var msgDiv = $('#' + conv.controls.messages);
        msgDiv.scrollTop(msgDiv[0].scrollHeight);
        var contacts_html = '';
        for (k in conv.contacts)
        {
            var ct = conv.contacts[k];
            contacts_html += '<span class="ct-nickname">' + ct.nickname + '</span><br />';
        }
        $('#' + conv.controls.contacts).html(contacts_html);
        tabs.tabs("refresh");
    }
}

function getConv(contactPuk, convId, contactId, contactNickname, myId) {
    if (typeof contactPuk !== 'undefined') {
        // Take care of ids if not passed
        if (typeof convId === 'undefined' || (!convId)) {
            convId = uniqueId();
        }
        if (typeof contactId === 'undefined' || (!contactId)) {
            contactId = uniqueId();
        }
        if (typeof contactNickname === 'undefined' || (!contactNickname)) {
            contactNickname = "Anonymous";
        }
        if (typeof myId === 'undefined' || (!myId)) {
            myId = uniqueId();
        }
        if (DEBUG >= 1) {
            console.log(":: GetConv :: enterin. Checking for existing conversation with id ["
                    + convId + "].");
        }
        var tmpConv = conversations[convId];
        if (typeof tmpConv !== 'undefined'
                && typeof tmpConv.contacts[contactId] === 'undefined')
        {   // wrong contactId ? look for a contact with this puk
            if (tmpConv.myId === contactId) {
                tmpContact = tmpConv.getContactByPuk(contactPuk);
                if (tmpContact)
                {
                    contactId = tmpContact.id;
                }
            }
        }
        if (typeof tmpConv !== 'undefined'
                && typeof tmpConv.contacts[contactId] !== 'undefined')
        {   // We already have this conversation and this 
            //  contact in this conversation , so just return it
            if (DEBUG >= 1) {
                console.log(":: GetConv :: found a conversation with this contact ["
                        + contactId + "]. Returning.");
            }
            // Set the conversation as not-new
            tmpConv.isNew = false;
            return tmpConv;
        } else {
            if (DEBUG >= 1) {
                console.log(":: GetConv :: testing contact's public key.");
            }
            // create temporary contact to test public key
            var tmpContact = new Contact(contactPuk, contactNickname, contactId);
            if (typeof tmpContact === 'object')
            {
                if (DEBUG >= 1) {
                    console.log(":: GetConv :: Created new Contact");
                    console.log(tmpContact);
                }
            } else {
                console.log(":: GetConv :: ERROR: building new contact failed. "
                        + "New conversation aborted. Public Key:");
                console.log(contactPuk);
                return false;
            }
            if (typeof tmpContact.rsaCrypto !== 'undefined' && tmpContact.rsaCrypto)
            {   // Contact crypto is valid, 
                if (typeof tmpConv !== 'undefined'
                        && typeof tmpConv.contacts[contactId] === 'undefined')
                {   // We already have this conversation but not
                    //  this contact in this conversation , 
                    //  contact will be added in the end to conv
                    console.log(":: GetConv :: adding contact ["
                            + contactId + "] to conversation [" + convId + "]");
                } else if (typeof conversations[convId] === 'undefined')
                {   // Conversation doesn't exist, create
                    var tmpConv = new Conversation(convId);
                    // Set ids
                    tmpConv.myId = myId;
                    // For now, we only have one contact in this conv
                    // firstContact won't change until firstContact logs out
                    tmpConv.firstContact = tmpContact.id;
                    if (DEBUG >= 1) {
                        console.log(":: GetConv :: Created new Conversation");
                        console.log(tmpConv);
                    }
                }
                // Add contact to conv and return conv
                if (typeof tmpConv !== "undefined" && typeof tmpContact !== "undefined")
                {
                    // Set contact.convId for reverse lookup
                    tmpContact.convId = tmpConv.id;
                    // lastContact will be each next contact added to the conv
                    tmpConv.lastContact = contactId;
                    tmpConv.contacts[tmpContact.id] = tmpContact;
                    // Add conversation to collection
                    conversations[tmpConv.id] = tmpConv;
                    return tmpConv;
                }
            } else {
                console.log(":: GetConv :: ERROR: something went wrong with the conversation creation.");
                console.log(tmpContact);
                return false;
            }
        }

    }
}


function add_message(queue, tmpJson) {
    /* @TODO: Here we should receive a JSON of format
     *    {myTime: timestamp, myself: true, msgId: newMsgId}
     * in case we sent it or
     *    {myTime: timestamp, contactId: tmpContact.id, msgId: newMsgId}
     * so both users have the same message queue in the same order
     */
    // Check parameters
    if (typeof queue !== 'undefined' && typeof tmpJson !== 'undefined' && typeof tmpJson === 'object') {
        // First check if we have tmpJson.message
        if (typeof tmpJson.message !== 'undefined' && tmpJson.message)
        {
            // Filter html tags from message
            tmpJson.message = filterHtml(tmpJson.message);
            // Save message in queue
            queue.messages.push(tmpJson);
            // Get conversation div
            var msg_element = $('#' + queue.divId);
            if (typeof queue.conv !== 'undefined')
            {   // This is a conversation queue
                var convMessages = queue.conv.getMessages();
                if (typeof convMessages !== 'undefined' && convMessages)
                {
                    msg_element.html(convMessages);
                }
                refresh_conversation(queue.conv);
                if (!tmpJson.myself)
                {
                    var notifTxt = (typeof tmpJson.nickname !== "undefined")
                            ? "New message from " + tmpJson.nickname + ".."
                            : "New message...";
                    deskNotify("Cryptweet", notifTxt, queue.conv.notifSound);
                }
            } else {  // This is the server's queue
                var tmpHtml = '';
                for (var i = 0; i < queue.messages.length; i++) {
                    var nick = queue.messages[i].server ? "Server" : "System";
                    tmpHtml += '<font class="server"><b>' + nick + ': </b>'
                            + queue.messages[i].message + '</font><br />';
                }
                msg_element.html(tmpHtml);
                msg_element.scrollTop(msg_element[0].scrollHeight);
            }
        }
    } else {
        console.log("There is a problem:", tmpJson);
        return false;
    }

}

function deskNotify(title, message, notifSound) {
    if (typeof $.ionSound !== "undefined" && typeof notifSound !== "undefined")
    {
        if (!MUTE)
        {
            $.ionSound.play(notifSound + ":0." + VOLUME);
        }
    } else {
        console.log(":: addMessage :: Problem with notification plugin.");
    }
    if (DESKNOT && !FOCUS)
    {

        // Create notification
        var notification = window.webkitNotifications.createNotification('icon.png', title, message);

        // Auto-hide after a while
        notification.ondisplay = function(event) {
            setTimeout(function() {
                event.currentTarget.cancel();
            }, 10000);
        };

        // Click event on notification
        notification.onclick = function() {
            // Focus on web-app
            window.focus();

            // Remove notification
            this.cancel();
        };

        // Show notification
        notification.show();
    }
}

/* CONTACT COMMUNICATION HANDLERS */
function processJson(decJson)
{
    if (typeof decJson.type !== 'undefined' && decJson.type === "contact_rsa_puk")
    {
        // We received a contact's public key
        // Create contact with associated RSA crypto 
        // Build Conversation and send ACK
        handle_contact_rsa_puk(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "message")
    {
        add_message(srv_messages, decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "ack_puk_received"
            && typeof decJson.convId !== 'undefined' && decJson.convId)
    {
        // We sent our public key to the contact
        // He received it, we now have an ID for this conv
        // create tab, stop waiting animation
        handle_ack_puk_received(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "ack_received"
            && typeof decJson.convId !== 'undefined' && decJson.convId)
    {
        // Contact key exchange is complete on both sides
        // Set border green, set contact's nickname
        handle_ack_received(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "contact_message"
            && typeof decJson.convId !== 'undefined' && decJson.convId)
    {
        // We received a contact's message
        // Add to coresponding conversation's queue
        handle_contact_message(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "resend"
            && typeof decJson.convId !== 'undefined' && decJson.convId)
    {
        handle_resend(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "invite_contact"
            && typeof decJson.convId !== 'undefined' && decJson.convId)
    {
        handle_invite_contact(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "contact_ping")
    {
        handle_contact_ping(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "contact_pong")
    {
        handle_contact_pong(decJson);
    } else if (typeof decJson.type !== 'undefined' && decJson.type === "conv_ping")
    {
        handle_conv_ping(decJson);
    } else {
        var errMsg = {message: "Unknown message type."};
        socket.emit('error', errMsg);
        add_message(srv_messages, errMsg);
    }
}

function handle_rsa_pubkey(data) {
    // update server's crypto
    SERVER_PUBKEY = data.puk;
    srv_crypto = load_keys(SERVER_PUBKEY);
    if (my_crypto)
    {   // We were already connected, 
        // inform server
        var reconnectJson = {type: "client_rsa_puk", puk: my_crypto.getPublicKey()};
        // Generate uniqueId for this packet
        var packetId = uniqueId();
        // Store json for re-sending if server decyption fails
        sent_packets[packetId] = reconnectJson;
        sent_packets[packetId].resend = "server";
        if (typeof Worker !== "undefined" && ENABLE_WORKERS)
        {
            encryptJsonThreaded(srv_crypto, reconnectJson, packetId, false);
        } else {
            sendEncrypted(socket, encryptJson(srv_crypto, reconnectJson), packetId);
            if (!isEmpty(conversations))
            {
                for (var conv in conversations) {
                    for (var c in conversations[conv].contacts) {
                        ask_resend(conversations[conv], conversations[conv].contacts[c]);
                    }
                }
            }
        }
    }
}

function handle_contact_ping(decJson) {
    if (typeof decJson.pingId !== 'undefined') {
        // this is a valid ping
        if (typeof decJson.puk !== 'undefined') {
            // we are given a public key, look into contact
            var tmpContact = getContactByPuk(decJson.puk);
            if (!tmpContact) {
                tmpContact = new Contact(decJson.puk);
                // store contact
                contacts[tmpContact.id] = tmpContact;
                tmpContact.global = true;
            }
            if (tmpContact && typeof tmpContact.rsaCrypto !== 'undefined' && tmpContact.rsaCrypto)
            {   // Contact crypto is valid, 
                var pongJson = {
                    type: "contact_pong",
                    pingId: decJson.pingId,
                    convId: decJson.convId,
                    nickname: $('#default_nickname').val()
                };
                console.log(":: handle_contact_ping :: sending CONTACT_PONG:");
                // Notify user
                add_message(srv_messages, {message: "Received PING["
                            + decJson.pingId + "], sending PONG", server: false});
                tmpContact.sendRSA(pongJson);
            }
        } else if (typeof decJson.puk !== 'undefined' && typeof decJson.pingId !== 'undefined'
                && typeof decJson.convId === 'undefined')
        {   // This is not a conversation ping
            var tmpContact = new Contact(decJson.puk);
            if (typeof tmpContact.rsaCrypto !== 'undefined' && tmpContact.rsaCrypto)
            {   // Contact crypto is valid, 
                var pongJson = {type: "contact_pong", pingId: decJson.pingId};
                console.log(":: handle_contact_ping :: sending CONTACT_PONG:");
                tmpContact.sendRSA(pongJson);
            }
        }
    }
}

function handle_contact_pong(decJson) {
    if (typeof decJson.pingId !== 'undefined')
    {    // Someone answered to a ping : check if we are awaiting a ping
        var tmpPing = pendingPings[decJson.pingId];
        if (typeof tmpPing !== 'undefined' && typeof tmpPing === 'object')
        {   // Ok we were awiting a pong for this ping ID
            // check if we were pinging this contact
            var tmpContact = contacts[tmpPing.yourId];
            if (typeof tmpContact !== 'undefined' && tmpContact.awaitingPong
                    && tmpContact.awaitingPong === decJson.pingId)
            {   // We were pinging this contact, unset flag
                tmpContact.awaitingPong = false;
                // Remove the ping from the queue
                delete pendingPings[decJson.pingId];
                // Notify user
                add_message(srv_messages, {message: "Received PONG to PING["
                            + decJson.pingId
                            + "]", server: false});
                if (typeof decJson.nickname !== 'undefined' && decJson.nickname !== '')
                {    // Contact provided a nickname in the pong, set it now
                    tmpContact.nickname = decJson.nickname;
                }
            }
            // If there is a connect flag set to true in the ping, it means that
            // we want to create a conversation with this contact
            if (typeof tmpPing.connect !== 'undefined' && tmpPing.connect)
            {   // Create a new conversation
                var convId = tmpPing.convId ? tmpPing.convId : false;
                // Set contactId to false so we create a contact 
                // specific to the new conv
                var tmpConv = getConv(tmpContact.rsaPuk, convId, false,
                        decJson.nickname);
                tmpPing.connect = false;
                // replace tmpContact with conv.lastContact
                tmpContact = tmpConv.contacts[tmpConv.lastContact];
                if (typeof tmpConv !== 'undefined') {
                    // Ok the conversation has been created, 
                    // send invitation and store in pending invitations
                    add_message(srv_messages, {message: "Created conversation["
                                + tmpConv.id + "], initiating RSA handshake...",
                        server: false});
                    tmpContact.invite(tmpConv);
                } else {
                    // looks like we don't have this conversation
                    add_message(srv_messages, {
                        message: "Conversation creation failed, aborting...",
                        server: false
                    });
                }
            }
        }

    }
}
function handle_conv_ping(decJson) {
    // @ToDo: not implemented, send conv_pong and reset conv_ping timeout  
    if (typeof decJson.pingId !== 'undefined') {
        // this is a valid ping
        if (typeof decJson.convId !== 'undefined' && typeof decJson.myId !== 'undefined') {
            // This is a valid conversation ping, check if we have it, else rebuild
            var tmpConv = conversations[decJson.convId];
            if (typeof tmpConv !== 'undefined') {
                // Test if we are pinging ourself
                if (decJson.myId === tmpConv.myId) {
                    // looks like we are receiving an invitation 
                    // for ourself, check if it is the case
                    var tmpContact = tmpConv.contacts[decJson.yourId];
                    // reset our id in this conversation with
                    tmpConv.myId = decJson.yourId;
                } else {
                    var tmpContact = tmpConv.contacts[decJson.myId];
                }
                var myNick = tmpConv.nickname;
                if (typeof tmpContact === 'undefined')
                {   // The Conv exists but not the contact, 
                    // this looks like an invitation from another contact
                    // create contact and add to the conv
                    if (decJson.myId === tmpConv.myId) {
                        // looks like we are receiving an invitation 
                        // for ourself, check if it is the case
                        tmpContact = tmpConv.getContactByPuk(decJson.puk);
                    } else {
                        // Just create a new contact
                        var tmpContact = new Contact(decJson.puk, decJson.nickname, decJson.myId);
                        tmpConv.contacts[decJson.myId] = tmpContact;
                    }
                }
            } else {
                // Conv doesn't exist yet, create contact from puk
                var tmpContact = new Contact(decJson.puk);
                contacts[tmpContact.id] = tmpContact;
                var myNick = $('#default_nickname').val();
            }
        }
    }
}

function handle_contact_rsa_puk(decJson) {
    // A contact sent us his public key
    if (typeof decJson.myId !== 'undefined' && decJson.myId)
    {
        var tmpContactId = decJson.myId;
    } else {
        var tmpContactId = false;
    }
    if (typeof decJson.puk !== 'undefined' && decJson.puk && typeof decJson.convId !== 'undefined')
    {   //            getConv(contactPuk,         convId,    contactId,  contactNickname,  myId)
        // Takes care of checking exiting conv and contact and returns accordingly
        var tmpConv = getConv(decJson.puk, decJson.convId, tmpContactId, decJson.nickname, decJson.yourId);

        // if something got wrong tmpConv should be false, otherwise
        if (typeof tmpConv !== "undefined" && tmpConv) {
            var tmpContact = tmpConv.getContactByPuk(decJson.puk);
            if (typeof tmpContact !== "undefined" && tmpContact) {
                var tmpContact = tmpConv.contacts[decJson.myId];
            }
            if (typeof tmpContact !== "undefined" && tmpContact) {
                // Format ACK
                /*var json_ack_puk_received = {type: "ack_puk_received",
                 convId: tmpConv.id,
                 myId: tmpConv.myId,
                 yourId: tmpContact.id,
                 nickname: tmpConv.nickname,
                 myTime: $.now()
                 };*/
                var json_ack_puk_received = new Ping("ack_puk_received",
                        tmpContact.id, tmpConv.id, tmpConv.myId);
                json_ack_puk_received.nickname = tmpConv.nickname;
                // Stop waiting for public key
                tmpContact.awaitingPuk = false;
                if (typeof pendingInvitations[tmpContact.id] !== "undefined") {
                    delete pendingInvitations[tmpContact.id];
                }
                // Notify user
                add_message(srv_messages, {message: "Received public key for contact["
                            + decJson.myId
                            + "], sending ack_puk_received...", server: false});
                // Send ACK
                tmpContact.sendRSA(json_ack_puk_received);
                // For new conv, just add conv
                if (tmpConv.isNew) {
                    // Set conversation as not new
                    tmpConv.isNew = false;
                    // If this is a new conversation, create tab
                    // Conversation's div has red border
                    // until handshake completes
                    addTab(tmpConv);
                }
                tmpConv = tmpContactId = tmpContact = false;
            }
        } else {
            console.log(":: handle_contact_rsa_puk :: problem with conversation :");
            console.log(tmpConv);
        }

    } else {
        console.log("Bad Public Key.");
    }
}

function handle_ack_puk_received(decJson) {
    // Contact received our public key
    if (typeof decJson.convId !== "undefined") {
        // look for the conversation, there must be one
        var tmpConv = conversations[decJson.convId];

        if (typeof tmpConv !== "undefined") {
            if (typeof tmpConv.myId === 'undefined' || tmpConv.myId === false) {
                tmpConv.myId = decJson.yourId;
            }
            if (typeof decJson.myId !== 'undefined') {
                var tmpContact = tmpConv.contacts[decJson.myId];
                if (typeof tmpContact === "undefined") {
                    // we don't have this contact in this conv, 
                    // try in pending invitations
                    var tmpContact = pendingInvitations[decJson.myId];
                    if (typeof tmpContact === "undefined") {
                        // not in ivitations, try in global contact list
                        var tmpContact = contacts[decJson.myId];
                        if (typeof tmpContact !== "undefined") {
                            // contact from global contact list, set new id
                            tmpContact.id = uniqueId();
                        }
                    } else {
                        // Found in pendingInvitations, delete invitation
                        // we don't need to invite this contact 
                        delete pendingInvitations[decJson.myId];
                        tmpConv.contacts[tmpContact.id] = tmpContact;
                    }
                } else {
                    // Found contact in conv, delete pending invitation
                    // if there is any
                    if (typeof pendingInvitations[decJson.myId] !== "undefined") {
                        delete pendingInvitations[decJson.myId];
                    }
                }

                // Now we should have a contact
                if (typeof tmpContact !== "undefined") {
                    // Reset contact's nickname
                    tmpContact.nickname = decJson.nickname;
                    // Stop waiting for public key
                    tmpContact.awaitingPuk = false;
                    // set convId for revers lookup
                    tmpContact.convId = tmpConv.id;
                    // update contact object in conversation
                    tmpConv.contacts[tmpContact.id] = tmpContact;
                    // create ack_receive object (ping of type "ack_received")
                    var json_ack_received = new Ping("ack_received", decJson.myId,
                            tmpConv.id, tmpConv.myId);
                    // add our nickname to the ACK
                    json_ack_received.nickname = tmpConv.nickname;
                    // send the ACK
                    tmpContact.sendRSA(json_ack_received);
                    // Notify user
                    add_message(srv_messages, {message: "Received ack_puk_received from contact["
                                + decJson.myId + "], sending ack_received...",
                        server: false});

                    // Contact received our puk, create tab if it's a new conv
                    if (tmpConv.isNew) {
                        // Set conversation as not new
                        tmpConv.isNew = false;
                        // If this is a new conversation, create tab
                        // Conversation's div has red border
                        // until handshake completes
                        addTab(tmpConv);
                    }
                    // User visual feedback, green for "Encryption enabled"
                    $('#' + tmpConv.controls.messages).css('border', '5px solid green');
                    refresh_conversation(tmpConv);
                    if (tmpContact.id !== tmpConv.firstContact) {
                        // this contact was invited to this conv, broadcast invitation
                        // Notify user
                        add_message(srv_messages, {message: "Broacasting invitation of contact["
                                    + tmpContact.id + "] to conv[" + tmpConv.id + "]",
                            server: false});
                        // broadcast invitation to the other contacts
                        var invite = new Ping("invite_contact", false, tmpConv.id, tmpConv.myId);
                        invite.puk = tmpContact.rsaPuk;
                        invite.contactId = tmpContact.id;
                        tmpConv.broadcastRSA(invite);
                    }
                } else {
                    console.log(":: handle_ack_puk_received :: ERROR: " +
                            "received ack_puk_received for non-existing contact.");
                }

            }
        } else {
            console.log(":: handle_ack_puk_received :: ERROR: " +
                    "received ack_puk_received for non-existing conversation.");
        }
    }
}

function handle_ack_received(decJson) {
    // The contact who invited us has received our ACK
    if (typeof decJson.convId !== 'undefined' && typeof decJson.myId !== 'undefined') {
        // look for the conversation, there must be one
        var tmpConv = conversations[decJson.convId];
        if (typeof tmpConv !== 'undefined') {
            // look for the contact, there must be one
            var tmpContact = tmpConv.contacts[decJson.myId];
            if (typeof tmpContact !== 'undefined' && typeof decJson.nickname !== 'undefined') {
                tmpContact.nickname = decJson.nickname;
                // Notify user
                add_message(srv_messages, {message: "Received ack_received from contact["
                            + tmpContact.id + "] for conv["
                            + tmpConv.id + "]",
                    server: false});
                // User visual feedback, green means handshake completed
                $('#' + tmpConv.controls.messages).css('border', '5px solid green');
                refresh_conversation(tmpConv);
            }
        }
    }
}

function handle_contact_message(decJson) {
    var tmpConv = conversations[decJson.convId];
    if (typeof tmpConv !== 'undefined') {
        var tmpDiv = tmpConv.messageQueue.divId;
        // look for the contact, there must be one
        var tmpContact = tmpConv.contacts[decJson.myId];
        if (typeof tmpContact !== 'undefined' && typeof decJson.nickname !== 'undefined') {
            // Update contact's nickname
            if (typeof decJson.nickname !== 'undefined')
            {
                tmpContact.nickname = decJson.nickname;
            }

            if (typeof decJson.msgId !== 'undefined'
                    && typeof tmpContact.lastMsgId !== 'undefined') {
                // Test if a message got lost
                if (decJson.msgId !== -1 && decJson.msgId > tmpContact.lastMsgId + 1)
                {   // A message got lost, ask RESEND             
                    console.log("Received contact_message with id to high." + tmpContact.lastMsgId + " < " + decJson.msgId);
                    if (!tmpContact.askingResend)
                    {   // We're not waiting for a retransmission from this contact
                        // ask contact to resend
                        ask_resend(tmpConv, tmpContact);
                    } else {
                        // We asked for resend check if this message is 
                        // already in the queue, if not add it
                        if (typeof tmpConv.messageQueue !== undefined) {
                            var newMsgId = (tmpContact.messages.push(decJson.message) - 1);
                            add_message(tmpConv.messageQueue, {
                                myTime: decJson.myTime,
                                contactId: tmpContact.id,
                                msgId: newMsgId,
                                message: decJson.message
                            });
                        }
                        if (typeof decJson.lastMsgId !== "undefined"
                                && decJson.lastMsgId === decJson.msgId)
                        {   // We have everything, reset asking to false
                            tmpContact.askingResend = false;
                            // Reset lastMsgId
                            tmpContact.lastMsgId = decJson.msgId;
                        }
                    }
                } else {
                    // Ignore all message before lastId
                    if (decJson.msgId !== -1 || decJson.msgId > tmpContact.lastMsgId)
                    {   // check for contact
                        var newMsgId = (tmpContact.messages.push(decJson.message) - 1);
                        add_message(tmpConv.messageQueue, {
                            myTime: decJson.myTime,
                            contactId: tmpContact.id,
                            msgId: newMsgId,
                            message: decJson.message});
                        tmpConv.contacts[decJson.myId].lastMsgId = decJson.msgId;
                    }
                }
            }
        }
    }
}

function ask_resend(tmpConv, tmpContact) {
    var tmpDiv = tmpConv.messageQueue.divId;
    // a message from this contact got lost
    // alert user
    $('<span class="tmpMsg">A message got lost, \
    asking for retransmission...</span>').appendTo('#' + tmpDiv);
    $('#' + tmpDiv).scrollTop($('#' + tmpDiv)[0].scrollHeight);
    refresh_conversation(tmpConv);
    tmpContact.askingResend = true;
    tmpContact.sendRSA({
        type: 'resend',
        myId: tmpConv.myId,
        convId: tmpConv.id,
        msgId: tmpContact.lastMsgId
    });
}

function handle_resend(decJson) {
    // test in firebug
    // conversations["convId"].myMessages.push("I'm missing")

    if (typeof decJson.msgId !== 'undefined'
            && typeof decJson.myId !== 'undefined')
    {

        console.log(":: handle_resend :: Got msgID " + decJson.msgId);
        var tmpConv = conversations[decJson.convId];
        var tmpContact = tmpConv.contacts[decJson.myId];
        var lastId = parseInt(decJson.msgId);
        var msgQ = tmpConv.myMessages;
        if (msgQ.length > 0)
        {
            for (var i = lastId + 1; i <= (msgQ.length - 1); i++)
            {
                var tmpJson = {type: "contact_message",
                    convId: tmpConv.id,
                    msgId: msgQ[i].msgId,
                    lastMsgId: msgQ.length,
                    nickname: tmpConv.nickname,
                    message: msgQ[i].message,
                    myId: tmpConv.myId,
                    yourId: decJson.myId,
                    myTime: msgQ[i].myTime
                };
                console.log(":: handle_resend :: Resending message #" + i);
                tmpContact.sendRSA(tmpJson);
            }
        }
    }
}

function handle_invite_contact(tmpJson) {
    // JSON json of format 
    // {type: "invite_contact", convId:, myId:, yourId:, contactId:, puk:}
    if (DEBUG >= 1) {
        console.log(":: handle_invite_contact :: we're asked to invite contact[" + tmpJson.contactId + "]");
    }
    if (typeof tmpJson.convId !== 'undefined' && typeof tmpJson.puk !== 'undefined'
            && typeof tmpJson.contactId !== 'undefined') {
        // First, check if it's not our pubkey, 
        // this is beeing broadcasted
        if (tmpJson.puk.trim() !== my_crypto.getPublicKey().trim()) {
            var tmpConv = conversations[tmpJson.convId];
            if (typeof tmpConv !== 'undefined') {
                // Did WE send the contact invitation ?
                if (tmpJson.contactId !== tmpConv.myId) {
                    // Is this contact already in our conv ?
                    // First check wih id, then with puk
                    if (typeof tmpConv.contacts[tmpJson.contactId] === "undefined") {
                        if (!tmpConv.getContactByPuk(tmpJson.puk)) {
                            tmpConv.inviteContact(tmpJson.puk, tmpJson.contactId);
                        }
                    }
                } else {
                    console.log(":: handle_invite_contact :: we're asked to invite ourself, not doing ;-}");
                }
                refresh_conversation(tmpConv);
            }
        } else {
            console.log(":: handle_invite_contact :: we're asked to invite ourself (pubkey="
                    + tmpJson.puk + ")");
        }
    }
}

/* FUNCTIONS FOR SENDING  */
function sendEncrypted(socket, arr_enc_chunks, packetId) {
    // Format JSON object
    var sendJson = {packetId: packetId, enc_msg_arr: arr_enc_chunks};
    if (DEBUG >= 2) {
        console.log("sendEncrypted :: sending encoded chunks array : ");
        console.log(sendJson);
    }
    socket.emit('sendcrypt', sendJson);
}
function resendPacket(socket, packetId) {
    var packet = sent_packets[packetId];
    if (typeof packet !== "undefined") {
        if (packet.resend === "server") {
            // Encrypt and send
            if (typeof Worker !== "undefined" && ENABLE_WORKERS)
            {
                encryptJsonThreaded(srv_crypto, packet, packetId, false);
            } else {
                sendEncrypted(socket, encryptJson(srv_crypto, packet), packetId);
            }
            sendEncrypted(socket, arr_enc_chunks, packetId);
        } else if (packet.resend === "contact") {
            delete packet.resend;
            if (typeof packet.yourId !== "undefined") {
                if (typeof packet.convId !== "undefined") {
                    // It's a conversation packet, lookup contact in conv
                    var tmpConv = conversations[packet.convId];
                    if (typeof tmpConv !== "undefined") {
                        var tmpContact = tmpConv.contacts[packet.yourId];
                        if (typeof tmpContact !== "undefined") {
                            tmpContact.sendRSA(packet);
                        }
                    }
                } else {
                    // This is not a conversation packet, lookup in global contacts list
                    var tmpContact = contacts[packet.yourId];
                    if (typeof tmpContact !== "undefined") {
                        tmpContact.sendRSA(packet);
                    }
                }
            }
        }
    }
}

function sendMessage(convId) {
    if (typeof conversations === 'object' && typeof convId !== 'undefined' && convId) {
        var conv = conversations[convId];
        if (conv)
        {
            var textbox = $('#' + conv.controls.userMessage);
            var tmpTxt = textbox.val();
            if (tmpTxt.trim() !== "") {
                // Add text to get id
                var newMsgId = conv.myMessages.push(tmpTxt) - 1;
                // Generate JSON with id
                var jsonMsg = {
                    type: "contact_message",
                    myTime: $.now(),
                    myself: true,
                    msgId: newMsgId,
                    message: tmpTxt
                };
                // Replace text with JSON
                conv.myMessages[newMsgId] = jsonMsg;
                // Add to conversation'S messages queue 
                add_message(conv.messageQueue, jsonMsg);
                // broadcast to everybody
                conv.broadcastRSA(jsonMsg);
            }
            // reset textbox
            textbox.val("");
            refresh_conversation(conv);
        }
    }
}

function sendPings() {
    // First send the pending invitations if we have any
    for (var cId in pendingInvitations) {
        var invContact = pendingInvitations[cId];
        var invConv = conversations[invContact.convId];
        if (typeof invContact !== "undefined" && typeof invConv !== "undefined") {
            add_message(srv_messages, {
                message: "Resending invitation to contact["
                        + invContact.id + "] for conv[" + invConv.id + "]...",
                server: false});
            invContact.invite(invConv);
        }
    }
    // Then take care of the remaining pings
    for (var pingId in pendingPings) {
        var tmpPing = pendingPings[pingId];
        var logMsg = "Sending ping[" + pingId + "]";
        if (typeof tmpPing.yourId !== 'undefined') {
            // This is a contact  ping
            if (typeof tmpPing.convId !== 'undefined') {
                // It also seem to belong to a conversation
                var tmpConv = conversations[tmpPing.convId];
            }
            if (typeof tmpConv !== 'undefined') {
                // we have this conv, look for contact
                var tmpContact = tmpConv.contacts[tmpPing.yourId];
                logMsg += " for conv[" + tmpConv.id + "]";
            }
            if (typeof tmpContact === "undefined") {
                // Contact is not in the conv already, 
                // check in global contacts list
                var tmpContact = contacts[tmpPing.yourId];
                if (typeof tmpContact !== "undefined") {
                    // Contact is in global contacts list, set flag
                    tmpContact.global = true;
                }
            }
        }
        // We did all we could to find the contact
        // if no found, delete the ping
        if (typeof tmpContact !== "undefined") {
            // contact found
            // set awaitingPong to pingId
            tmpContact.awaitingPong = pingId;
            // send the ping
            tmpContact.sendRSA(tmpPing);
            // Decrease pending pings
            tmpPing.retry = tmpPing.retry - 1;
            // log with actual retry
            logMsg += "to contact[" + tmpContact.id + "] ("
                    + tmpPing.retry + " more)...";
            add_message(srv_messages, {
                message: logMsg,
                server: false
            });
            if (tmpPing.retry <= 0) {
                // it was the last retry, remove ping
                delete pendingPings[pingId];
                // delete contact from conv, 
                // and if there's nobody left delete conv
                delete tmpConv.contacts[tmpPing.yourId];
                if (isEmpty(tmpConv.contacts)) {
                    delete conversations[tmpConv.id];
                }
                if (typeof tmpPing.connect !== "undefined"
                        && tmpPing.connect) {
                    // alert user that the contact seems to be offline
                    var alertMsg = "The contact you're trying to connect to seem to be offline.\n"
                            + "Public key:\n" + tmpContact.rsaPuk;
                    add_message(srv_messages, {
                        message: alertMsg, server: false});
                    alert(alertMsg);
                }
            } else {
                // save new retry value
                pendingPings[pingId] = tmpPing;
            }
        } else {
            delete pendingPings[pingId];
        }
    }
    // Delete vars
    delete invConv, invContact, tmpConv, tmpContact, cId;

// Now ping each contact in each conversation
// if we're not pinging this contact already
    for (var convId in conversations)
    {
        var tmpConv = conversations[convId];
        if (!tmpConv.isNew) {
            tmpConv.ping();
        }
    }
}

function getContactByPuk(puk) {
    for (var cId in contacts)
    {
        if (typeof contacts[cId].rsaPuk !== "undefined") {
            if (puk.trim() === contacts[cId].rsaPuk.trim())
            {   // Return the first one, we should never have
                // two contacts with the same public key !
                return contacts[cId];
            }
        } else {
            return false;
        }
    }
    // If we found nothing return false
    return false;
}
;


/* OBJECTS DEFINITIONS */
/* CONVERSATION OBJECT */
function Conversation(convId) {
    // ID of the conversation (random)
    if (typeof convId === 'undefined') {
        convId = uniqueId();
    }
    // flag to know if we are in conversation creation.
    this.isNew = true;
    // Set the ID
    this.id = convId;
    // To store the UUID generated by the contact
    this.myId = false;
    // To store the nickname in this conv
    this.nickname = ($('#default_nickname').val() ? $('#default_nickname').val() : "Anonymous");
    // To alert contacts of this conv when changing nickname     this.previousNick = false;
    // To store the crypto(s)
    this.crypto = null;
    // Useful to remember the first and
    // the last-added contact in this conv
    this.firstContact = null;
    this.lastContact = null;
    // To store the contacts in this conv
    this.contacts = {};
    // To store a copy of what the user sent
    // Use for retransmitting lost messages
    this.myMessages = [];
    // Sound for notifications for this conversation
    this.notifSound = defaultNotifSound;
    // Controls ids
    this.controls = {
        nickname: this.id + "_nickname",
        contactPuk: this.id + '_contact_public_key',
        userMessage: this.id + '_uncrypted',
        messages: this.id + '_conversation',
        btInvite: this.id + '_bt_send_puk',
        btSend: this.id + '_bt_send',
        myPuk: this.id + '_public_key',
        contacts: this.id + '_contacts',
        soundSelector: this.id + '_soundSelector'
    };
    // Initialize the conversation's messages queue
    this.messageQueue = {divId: this.controls.messages, conv: this, messages: []};
}

Conversation.prototype.broadcastRSA = function(tmpJson) {
    if (typeof tmpJson === 'object') {
        if (tmpJson.type === "contact_message")
        {
            var system = (typeof tmpJson.system === 'undefined' ? false : true);
            var msgId = (typeof tmpJson.msgId === 'undefined' ? -1 : tmpJson.msgId);
            var myTime = (typeof tmpJson.myTime === 'undefined' ? $.now() : tmpJson.myTime);
            var sendJson = {type: "contact_message",
                myTime: myTime,
                convId: this.id,
                msgId: msgId,
                message: tmpJson.message,
                myId: this.myId,
                yourId: false
            };
            if (system) {
                sendJson.system = true;
            } else {
                sendJson.nickname = this.nickname;
            }
        } else {
            // for other packets just send JSON as it is
            var sendJson = tmpJson;
        }
        if (typeof sendJson === 'object') {
            for (c in this.contacts) {
                // For each contact, set yourId in JSON
                sendJson.yourId = c.id;
                this.contacts[c].sendRSA(sendJson);
            }
        } else {
            console.log(":: broadcastRSA :: No recognized type, not sending anything.");
        }
    } else {
        console.log(":: broadcastRSA :: expecting object, received [" + typeof tmpJson + "].");
    }
};
Conversation.prototype.getMessages = function() {
    /* Queue objects' format
     *    {myTime: timestamp, myself: true, msgId: newMsgId}
     * in case we sent it or
     *    {myTime: timestamp, contactId: tmpContact.id, msgId: newMsgId}
     * if it's a contact's message
     * so both users (should) have the same queue
     */
    // Sort messages by timestamp
    // Add sort function on messages array
    this.messageQueue.messages.sort(function(a, b) {
        return a.myTime - b.myTime;
    });
    var tmpHtml = '';
    for (var i = 0; i <= this.messageQueue.messages.length - 1; i++) {
        // Reinit vars to avoid confusion, we're in a for loop
        var tmpContact, nickClass, nickname, message, time = false;
        var qi = this.messageQueue.messages[i];
        // Is it our message or a contact's message ?
        if (typeof qi.myself === 'undefined' || (!qi.myself))
        {   // contact's message
            tmpContact = this.contacts[qi.contactId];
            nickClass = "contact";
            nickname = ((typeof tmpContact.nickname === 'undefined'
                    || !tmpContact.nickname) ? 'Anonymous' : tmpContact.nickname);
            message = tmpContact.messages[qi.msgId];
        } else {
            // our message
            nickClass = "myself";
            nickname = this.nickname;
            message = this.myMessages[qi.msgId].message;
        }
        if (typeof qi.myTime !== 'undefined')
        {
            time = new Date(qi.myTime).toLocaleTimeString();
        } else {
            time = 'never';
        }
        tmpHtml += '<font class="time">[' + time + ']</font> <font class="' + nickClass + '"><b>' + nickname + ': </b>'
                + message + '</font><br />';
    }
    return tmpHtml;
};

Conversation.prototype.getContactByPuk = function(puk) {
    for (var cId in this.contacts)
    {
        if (puk.trim() === this.contacts[cId].rsaPuk.trim())
        {   // Return the first one, we should never have
            // two contacts with the same public key !
            return this.contacts[cId];
        }
    }
    // If we found nothing return false
    return false;

};

Conversation.prototype.ping = function() {
    // Send a ping of type "conv_ping" to each contact in this conv
    for (var cId in this.contacts) {
        var tmpContact = this.contacts[cId];
        // Create ping
        var tmpPing = new Ping("conv_ping", tmpContact.id, this.id,
                this.myId, this.myMessages.length);
        tmpContact.sendRSA(tmpPing);
    }
};

Conversation.prototype.inviteContact = function(puk, contactId) {
    if (typeof contactId !== "undefined") {
        // First check with id in the global contacts with id
        var tmpContact = contacts[contactId];
        if (typeof tmpContact === "undefined") {
            // not found, look in this.contacts with id
            var tmpContact = this.contacts[contactId];
            if (typeof tmpContact !== "undefined") {
                console.log(":: Conversation.inviteContact :: contact's id already in conv, aborting.");
                return false;
            }
        }
    } else {
        // No contactId given, set a uniqueId
        contactId = uniqueId();
    }
    if (typeof tmpContact === "undefined" && typeof puk !== 'undefined') {
        // Check in this conversation for this pubkey
        var tmpContact = this.getContactByPuk(puk);
        if (!tmpContact) {
            // Check in the global contacts list with this pubkey
            var tmpContact = getContactByPuk(puk);
            if (tmpContact) {
                // contact is in global contacts list
                // set global flag
                tmpContact.global = true;
            }
        } else {
            console.log(":: Conversation.inviteContact :: contact's puk already in conv, aborting.");
            return false;

        }
    }
    // If we didn't find a contact with this id or this pubKey, 
    // Create a new one and put it in this conv, overwrite id
    tmpContact = tmpContact ? tmpContact : new Contact(puk, false, contactId);
    // Now we surely have a contact
    if (tmpContact && !tmpContact.awaitingPong) {
        if (typeof tmpContact.global !== "undefined" && tmpContact.global) {
            // this is a global contact, create a new one for this conv
            var newContact = new Contact(tmpContact.rsaPuk, false, contactId);
            tmpContact = newContact;
            delete newContact;
        }
        // set contact.convId for reverse lookup
        tmpContact.convId = this.id;
        // Create ping
        var tmpPing = new Ping("contact_ping", tmpContact.id, this.id,
                this.myId, this.messageQueue.messages.length);
        // Set our puk
        tmpPing.puk = my_crypto.getPublicKey();
        tmpPing.connect = true;
        // add to ping queue            
        pendingPings[tmpPing.pingId] = tmpPing;
        // mark this contact as awaitingPong
        tmpContact.awaitingPong = tmpPing.pingId;
        // Store / update the contact in global contacts list
        contacts[tmpContact.id] = tmpContact;
        // call sendPings
        sendPings();
        return tmpContact;
    }

};
/* CONTACT OBJECT */
function Contact(rsaPuk, nickname, contactId) {
    if (typeof rsaPuk === 'undefined' || (!rsaPuk)) {
        return false;
    }
    if (typeof nickname === 'undefined' || (!nickname)) {
        nickname = "Anonymous";
    }
    if (typeof contactId !== 'undefined') {
        this.id = contactId;
    } else {
        this.id = uniqueId();
    }
    this.convId = false;
    this.rsaPuk = rsaPuk;
    this.rsaCrypto = load_keys(rsaPuk);
    this.nickname = nickname;
    this.tmpKey = "";
    this.sessionCrypto = "";
    // Used to detect lost messages
    this.lastMsgId = -1;
    // Contacts_messages     
    this.messages = [];
    this.askingResend = false;
    this.awaitingPong = false;
    this.awaitingPuk = false;
    this.invitation = false;
    this.online = false;
    this.status = "offline";
}

Contact.prototype.sendRSA = function(json) {
    var srvJson = false;
    // Generate uniqueId for this packet
    var packetId = uniqueId();
    if (typeof srv_crypto !== 'undefined' && srv_crypto) {
        if (DEBUG >= 1) {
            console.log(":: Contact.sendRSA :: sending to client:");
            console.log(json);
        }
        if (typeof Worker !== "undefined" && ENABLE_WORKERS)
        {
            encryptJsonThreaded(this.rsaCrypto, json, packetId);
        } else {
            var contactJson = {
                type: "contact_message",
                message: encryptJson(this.rsaCrypto, json)
            };
            srvJson = encryptJson(srv_crypto, contactJson);
            // Store contact-encrypted json for re-sending 
            // if server decyption fails
            sent_packets[packetId] = srvJson;
            sent_packets[packetId].resend = "server";
            if (srvJson)
            {
                if (DEBUG >= 3) {
                    console.log(":: Contact.sendRSA :: sending to server:");
                    console.log(srvJson);
                }

                sendEncrypted(socket, srvJson, packetId);
            }
        }
    } else {
        console.log(":: Contact.sendRSA :: No server crypto loaded !");
    }
};

Contact.prototype.ping = function(json) {
    if (typeof srv_crypto !== 'undefined' && srv_crypto &&
            typeof my_crypto !== 'undefined' && my_crypto) {
        // Create a new ping object
        var ping = new Ping("contact_ping", this.id);
        if (typeof json !== "undefined") {
            if (typeof json.puk !== "undefined") {
                ping.puk = json.puk;
            }
            if (typeof json.convId !== "undefined") {
                ping.convId = json.convId;
            }
        }
        this.awaitingPong = ping.id;
        this.sendRSA(ping);
        return ping;
    } else {
        return false;
    }
};

Contact.prototype.invite = function(tmpConv) {
    if (typeof tmpConv !== "undefined")
    {
        this.convId = tmpConv.id;
    }
    if (!this.invitation) {
        this.invitation = new Ping("contact_rsa_puk", this.id, this.convId, tmpConv.myId);
        this.invitation.puk = my_crypto.getPublicKey();
        this.invitation.nickname = tmpConv.nickname;
    }
    if (typeof pendingInvitations[this.id] === "undefined") {
        // Store invitation in case the first get lost
        pendingInvitations[this.id] = this;
    }
    // Set flag that we are awaiting the puk of this contact
    this.awaitingPuk = true;
    this.sendRSA(this.invitation);
};

/* CONTACT OBJECT */
function Ping(type, contactId, convId, myId, myLastMsgId, yourLastMsgId) {
    // @ToDo: use the ping/pong packets to synchronize clocks
    // - we need to store the ping, with it's retry-number and the time we sent it
    // - when we receive a ping, return a pong with pingId, retry-number, 
    //   time of receiving the ping, time of sending the pong
    // - when we receive a pong, calcualte the contact's time delta :
    //  delay = ( timePongReceived - timePongSent ) 
    //     => the time for the pong packet to arrive
    //  ( ( timePingSent +  ) - time ) and store it in contact
    // - when we receive a contact_message, set myTime = (myTime + delta)
    if (typeof type !== "undefined")
    {
        this.type = type;
    } else {
        this.type = "wild_ping";
    }
    var tmpDate = new Date();
    this.myTime = tmpDate.getTime();
    delete tmpDate;
    // Generate uniqueId
    this.pingId = uniqueId();
    this.retry = PING_RETRY;
    if (typeof contactId !== "undefined") {
        this.yourId = contactId;
    }
    if (typeof convId !== "undefined") {
        this.convId = convId;
    }
    if (typeof myId !== "undefined") {
        this.myId = myId;
    }
    if (typeof myLastMsgId !== "undefined") {
        this.myLastMsgId = myLastMsgId;
    }
    if (typeof yourLastMsgId !== "undefined") {
        this.yourLastMsgId = yourLastMsgId;
    }
}
