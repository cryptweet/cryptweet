/* GLOBALS FOR FUNCTIONS */
// Config, feel free to adapt
// URL of the actual Craptweet service 
var SERVICE_URL = 'http://192.168.178.125:80';
var SERVICE_PORT = '80';

// DEBUG LEVEL
var DEBUG = 1;
// TTL of a ping
var PING_RETRY = 6;
// delay in seconds between two calls to sendPings
var PING_INTERVAL = 15;
// Enable/Disable WebWorkers functionnality
var ENABLE_WORKERS = true;
// Enable user to disable sound notifications
var MUTE = false;
var VOLUME = 9;
// Set a default sound, see IonSound jQuery plugin for a list
// The list is also in a popup in conversations
var defaultNotifSound = 'beer_can_opening';
// END CONFIG

// :: ATTENTION :: Changing anything below this line is strongly discouraged
// unless you know what you're doing of course ;)
var my_crypto = false;

// FLAGS
var KEYS_LOADED = false;
var FOCUS = true;
// Focus change : only one function name for all browser
if (/*@cc_on!@*/false)
{ // check for Internet Explorer
    document.onfocusin = onFocus;
    document.onfocusout = onBlur;
} else {
    window.onfocus = onFocus;
    window.onblur = onBlur;
}



// VARS FOR STORING OBJECTS AND INTERVALS
// used to store the conversations
var conversations = {};
// used to store the contacts who are not in a conv
var contacts = {};
// used to store the pings we're sending
// in order to retry and decrease
var pendingPings = {};
// used to store the invitations, 
// so that we can re-invite if a packet get lost
var pendingInvitations = {};
// used to store active notifications
var notifications = {};
// @ToDo: dirty hack: used to store temporarily sent packets
// for the case the server failed to decrypt, then we re-encrypt
//  the packet... To be able to do that we have to send the
//  packet id in clear-text... THAT SHOULD NOT HAPPEN !!
var sent_packets = {};

// pingInterval
var pingInterval = null;
var socket = null;

// SERVER VARIABLES 
// Server's Public Key 
var srv_crypto = false;
var SERVER_PUBKEY = false;
// Server's messages queue
var srv_messages = {divId: 'server_msg', messages: []};
// END SERVER VARIABLES 

// TRICKS
// Speed up calls to hasOwnProperty
var hasOwnProperty = Object.prototype.hasOwnProperty;
// END TRICKS

// DETECT SUPPORT FOR HTML5 DESKTOP-NOTIFICATIONS 
if (window.webkitNotifications) {
    console.log('Your web browser does support notifications!');
    var DESKNOT = true;
} else {
    console.log('Your web browser does not support notifications!');
    var DESKNOT = false;
}
window.onload = function() {
    if (DESKNOT) {
        window.onclick = function() {
            // Ask for permission
            window.webkitNotifications.requestPermission();
        };
    }
    /* CLIENT VARIABLES */
    var my_pubkey = $("#my_pubkey");
    var contact_pubkey = $("#contact_public_key");
    var my_privkey = $("#private_key");
    var loadMyKeysButton = $("#bt_load_keys");
    var genKeysButton = $("#bt_gen_keys");
    var connectContactButton = $("#bt_connect_contact");
    /* END CLIENT VARIABLES */


    // Start connection  
    socket = io.connect(SERVICE_URL);
    socket.on('connect_failed', function(data) {
        console.log("Connect FAILED !!");
    });
    socket.on('server_rsa_pubkey', function(data) {
        handle_rsa_pubkey(data);
    });
    socket.on('message', function(data) {
        data = process_data(srv_crypto, data);
        data.message = '<font class="message">' + data.message + '</font>';
        add_message(srv_messages, data);
    });
    socket.on('error', function(data) {
        if (data.message === "ERR_CRYPTO_FAILED")
        {
            loadMyKeys();
            data.message = "Server had a problem with our crypto, reloading keys.";
        } else if (data.message === "DECRYPT_FAILED") {
            if (typeof data.packetId !== "undefined")
            {
                data.message = "Server didn't decrypt last packet, trying resend...";
                resendPacket(socket, data.packetId);
            } else {
                data = process_data(srv_crypto, data);
                data.message = '<font class="error">ERROR: ' 
                        + data.message + '. Data:<pre>' 
                        + JSON.stringify(data) + '</pre></font>';
            }
         } else if (data.message === "UNKN_MSG_TYPE") {
            console.log("UNKN_MSG_TYPE: object, decrypted");
            console.log(data.object);
            console.log(data.decrypted);
        } else {
            data = process_data(srv_crypto, data);
            data.message = '<font class="error">ERROR: ' + data.message + '</font>';
        }
        add_message(srv_messages, data);
    });
    socket.on('info', function(data) {
        data = process_data(srv_crypto, data);
        data.message = '<font class="info">INFO: ' + data.message + '</font>';
        add_message(srv_messages, data);
    });
    socket.on('sendcrypt', function(data) {
        if (DEBUG >= 3)
        {
            console.log("SENDCRYPT received, data:\n");
            console.log(data);
        }
        if (typeof data.enc_msg_arr !== 'undefined' && data.enc_msg_arr !== "")
        {   // Try to decrypt the message and rebuild the JSON
            // If workers are enabled, the decrypted JSON
            // is processed in a WebWorker, else it is 
            // returned and stored in decJson
            receiveEncrypted(my_crypto, data.enc_msg_arr);
        } else {
            socket.emit('error', {message: "Expecting enc_msg_arr in data, but none or an empty array was found."});
        }
    });


    /**           BUTTONS               */
    loadMyKeysButton.on('click', function() {
        if ($("#private_key")[0].value !== "")
        {
            loadMyKeys();
        } else {
            alert("Please select a private key first.\n"
                    + "If you don't have any, you can generate some here.");
        }
    });
    genKeysButton.on('click', function() {
        genMyKeys();
    });
    connectContactButton.on('click', function() {
        console.log('Sending public key');
        // Create new contact
        var tmpContact = new Contact(contact_pubkey.val());
        if (tmpContact)
        {
            contacts[tmpContact.id] = tmpContact;
            var tmpPing = tmpContact.ping({puk: my_crypto.getPublicKey()});
            tmpPing.connect = true;
            tmpPing.nickname = $('#default_nickname').val();
            // add to ping queue            
            pendingPings[tmpPing.pingId] = tmpPing;
            tmpContact.sendRSA(tmpPing);
        }
    });

    /* JQUERY-UI STUFF COMES HERE */
    $(function() {
        var tabs = $("#tabs").tabs();
        tabs.find(".ui-tabs-nav").sortable({
            axis: "x",
            stop: function() {
                tabs.tabs("refresh");
            }
        });
    });

    // FileReader Helper
    $('#bt_pick_prk').fileReaderJS({
        readAsDefault: 'Text',
        on: {
            load: function(e, file) {
                $("#private_key").val(e.target.result);
                loadMyKeys();
            }

        }
    });
    $('#bt_pick_puk').fileReaderJS({
        readAsDefault: 'Text',
        on: {
            load: function(e, file) {
                $("#contact_public_key").val(e.target.result);
            }

        }
    });

    // Set pinging interval
    pingInterval = setInterval(function() {
        sendPings();
    }, PING_INTERVAL * 1000);

    // Initialize IonSound jQuery plugin for notifications
    $.ionSound({
        sounds: [
            'beer_can_opening',
            'bell_ring',
            'branch_break',
            'button_click',
            'button_click_on',
            'button_push',
            'button_tiny',
            'camera_flashing',
            'camera_flashing_2',
            'cd_tray',
            'computer_error',
            'door_bell',
            'door_bump',
            'glass',
            'keyboard_desk',
            'light_bulb_breaking',
            'metal_plate',
            'metal_plate_2',
            'pop_cork',
            'snap',
            'staple_gun',
            'tap',
            'water_droplet',
            'water_droplet_2',
            'water_droplet_3'
        ],
        path: './sounds/',
        multiPlay: false,
        volume: '0.5'
    });

};

