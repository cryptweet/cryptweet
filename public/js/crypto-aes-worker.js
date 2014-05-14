
/* MAIN SCRIPT */
/* Checking if Web Workers are supported by the browser */
if (window.Worker) {
  // Getting references to the 3 other HTML elements
  var _txtPlaintext = document.getElementById("txtPlaintext");
  var _txtCiphertext = document.getElementById("txtCiphertext");
  var _txtVerification = document.getElementById("txtVerification");
  // button
  var _cmdEncrypt = document.getElementById("cmdEncrypt");
  var _cmdDecrypt = document.getElementById("cmdVerify");

  // Instantiating the Worker
  var wk = new Worker('./webworker/mythread.js');

  // Getting ready to handle the message sent back by the worker
  wk.addEventListener("message", function (event) 
  {
    var json_string = event.data;

    var jsObject = eval("(" + json_string + ")");
    var type = jsObject.type;
    if (strcmp(type, "encrypt") == 0) {
        _txtCiphertext.value = event.data;
    } 
    else if (strcmp(type, "decrypt") == 0) {
        _txtVerification.value = jsObject.plaintext;
    } 
  }, false);
	
  _cmdEncrypt.addEventListener("click", function (event) 
  {    
    // array json object
    var json;
    json = {
            keySize: 128,
            plaintext: "plaintext",
            passphrase: "passphrase"
           };
    var json_string = JSON.stringify(json);

    // We're now sending messages via the 'encrypt' command 
    wk.postMessage(new WorkerMessage('encrypt', json_string));

  }, false);

  _cmdDecrypt.addEventListener("click", function (event) 
  {	
    // da json_string a json_data_object
    var jsObject = eval("(" + _txtCiphertext.value + ")");

    // array json object
    var json;
    json = {
            keySize: 128,
            ciphertext: jsObject.ciphertext,
            passphrase: "passphrase"
           };
    var json_string = JSON.stringify(json);

    // We're now sending messages via the 'decrypt' command 
    wk.postMessage(new WorkerMessage('decrypt', json_string));

  }, false);

}

function WorkerMessage(cmd, parameter) 
{
    this.cmd = cmd;
    this.parameter = parameter;
}

/* END MAIN SCRIPT */


/* WORKER */

/************************* LIBRARY *************************/
importScripts('./js/my_libjs.js', 
              './js/my_util.js',
              './js/form.js');

/************************* LIBRARY CRYPTOJS *************************/
importScripts('./aes/aes.js',
              './hash/md5/md5.js',
              './hash/sha1/sha1.js',
              './hash/sha256/sha256.js');


function messageHandler(event) 
{
    // Accessing to the message data sent by the main page
    var messageSent = event.data;
	
    // Testing the command sent by the main page
    switch (messageSent.cmd) 
    {
	 
        case 'encrypt': 

            var receive_json_string = messageSent.parameter;
            var jsObject = eval("(" + receive_json_string + ")");
            var plaintext = jsObject.plaintext;
            var passphrase = jsObject.passphrase;

            var ciphertext = Crypto.AES.encrypt(plaintext, passphrase);

            // array json object
            var json;
            json = {
                    cipher: "aes",
                    type: "encrypt",
                    ciphertext: base64_encode(ciphertext)
                   };

            var send_json_string = JSON.stringify(json);
            this.postMessage(send_json_string);

           break;

        case 'decrypt':

            var receive_json_string = messageSent.parameter;
            var jsObject = eval("(" + receive_json_string + ")");
            var ciphertext = base64_decode(jsObject.ciphertext);
            var passphrase = jsObject.passphrase;

            var plaintext = Crypto.AES.decrypt(ciphertext, passphrase);

            // array json object
            var json;
            json = {
                    cipher: "aes",
                    type: "decrypt",
                    plaintext: plaintext
                   };

            var send_json_string = JSON.stringify(json);
            this.postMessage(send_json_string);

           break;

        default:
            this.postMessage("invalid command!!!");
           break;

    }
	
}

// Defining the callback function raised when the main page will call us
this.addEventListener('message', messageHandler, false);
 
/* END WORKER */
