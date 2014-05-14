Cryptweet
=========

Full-web encrypted communication system (server and client). Concepts and technologies used in this project: RSA, AES, Diffie-Hellman (ECDH), Off-The-Recor (OTR), NodeJS, jQuery, HTML5

## Why Cryptweet

[*German translation below...*](#user-content-german)

This project started with the idea of a full-web-secure-chat-system, and while there are a lot of interesting solutions out there, I couldn't find anything that meets the following requirements:

 - **OPEN-SOURCE** : where both client-code and server-code are in the same language, so that anybody can understand it without having to learn tons of things. 

   => Cryptweet is programmed in javascript, comments should explain everything
      the server side is based on node-js, the client side on jQuery/html/css

 - **NOT SERVICE-ORIENTED** : anybody can easily set up a server and let a community communicate with each other.

   => Allthough you're free to set up your own Cryptweet-service, with registered users, password authentication, registration fee or whatever you need, this is not part of the system. To use Cryptweet, one only needs the public key of its contact and the address of a running server his contact is connected to. 
   NO ACCOUNT, NO PASSWORD, NO REGISTRATION.

 - **NOTHING TO INSTALL** : you can use it on any platform without having to install a plugin or a software (a lot of people don't have the system-permissions to modify the system they are using)

   => Cyptweet works (or should, in the end) on (almost) any platform with a quite modern browser.
      Feel encouraged to report any browser-version where it doesn't work as expected

 - **END-TO-END ENCRYPTION** : the server is blind, it never knows who is talking to who, and what is being said, and you can easily verify it.

   => the Cryptweet server receives only encrypted packets, and sends everything back to everybody (something like bitmessage). Only the one who has the private key can decrypt the packet, and it makes it very difficult for anybody to observe the communication (aka traffic shaping) 

## How it works

### THE SERVER

- should be hosted on HTTPS, with a valid certificate, in order to establish a trusted connection to the client's code (avoid man-in-the-middle changing the client's code)
- generates a new session private key at startup
- waits for connections
- establish an RSA-tunnelled socket with any client offering a valid encrypted packet containing a valid RSA public key
- receives packets encrypted with it's public key
- sends each decrypted packet to each client, after having encrypted it again with the client's public key (broadcast)
- ToDo: plugin for saving offline-messages, using a permanent extra-private key, managed by the plugin

### THE CLIENT

- manages the contacts and conversations
- loads or generates the user's private key
- sends the user's public key to the server, after having encrypted it with the server's public key
- when the user provides a valid contact's public key, the client initiates a new conversation with this contact, that means 
    1. encrypting the user's public key with the contact's public key
    2. encrypting the contact-encrypted-packet with the server's public key
    3. sending this double-encrypted packet to the server 
    4. on the server-side, the packet will be decrypted, and 'broadcrypted' to all 
       current sockets with their own crypto, including the one sending the packet
- if the contact receives the packet and can decrypt it, he will answer using the same mechanism as for receiving the public key (ACK_PUK_RECEIVED).
- the user initiating the connection then answers he received the ACK
- - ToDo: after this handshake, the clients should negociate a common symmetric key for this conversation and agree on a timeout for using the next key. (maybe still keep the old key for a while if a packet got lost)
- when users are in a conversation, they have the ability to invite other contacts to participate to the conversation, by adding the contact's public key to the conversation.
- ToDo: plugin for offline-messages
- ToDo: plugin for file sharing


## How you can help
 As this project is completely money-free, 
  - we can't afford a hosting solution, so we need people/companies to host demo-versions of the system (on HTTPS, to avoid man-in-the-middle attack). The more we are, the more it is secure (still to be proven ;-)
  - we can't afford a root-certificate, and the security of system relies on the HTTPS-protocol, so we need at least one root-certificate to be able to sign certificates for the domains hosting the demos

## @ToDo:

### Next functionnalities
    - First of all, implement a plugin architecture (client- AND server-side) so that new functionnalities (most of the following) can be added without changing the core
    - Plugin for the server, enabling the possibility of offline messages
    - Plugin for the client, enabling users to share files
    
### Design
    - Step-by-step login with show/hide of elements
    - Theme-Plugin for the UI(jQuery-UI-based) so that users can easily switch theme 
    - Sound- and Desktop notifications
    
### Network
    - Implement a relay mechanism so that several server can communicate with each-other, enabling people connected to server A to send packets to servers B, C, and so on.
    
### Security
    - Plugin system for cryptography, so that users can easily switch the crypto-lib in use for a session/conversation
    - Implement a mechanism on the client-side to make sure that the code has not been modified by the person hosting the service (is it possible at all ?) 
    - Implement conversation's OTR-like-crypto in AES so that participants of a cnversation share the same temporary-key, that changes regularily (doing so, we encrypt only once for all --it is more efficient-- and every n packets, the conversation's key changes, making the decryption of the whole conversation really difficult, aka OTR)
    
### Installation
    - Script to debbootsrap, intall and configure a server in a chrooted environment 




# GERMAN
## Warum Cryptweet 
Das Projekt begann mit der Idee eines kompletten Web-sicheren-Chat-Systems, und obwohl es eine Menge interessante Lösungen hier draussen gibt, konnte ich nichts finden, was die folgenden Anforderungen erfüllt: 


 - **OPEN-SOURCE**: wo sowohl Clienten als auch Server-Code in der gleichen Sprache sind, so dass jeder es verstehen kann ohne tausend Sachen lernen zu müssen. 

   => Cryptweet ist in Javascript programmiert, Kommentare sollten alles erklären 
      die Server-Seite basiert auf node-js, die Clienten-Seite auf jQuery/html/css

 - **NICHT SERVICE-ORIENTIERT**: jeder kann leicht einen Server erstellen und eine Community miteinander kommunizieren lassen. 

   => Obwohl es dir frei steht, deinen eigenen Cryptweet-Service mit registrierten Benutzern bereitzustellen, mit Passwort-Authentifizierung, Anmeldegebühr oder was auch immer du benötigst, ist dies kein Teil des Systems. Um Cryptweet zu benutzen braucht man nur den öffentlichen Schlüssel seines Kontaktes und die Adresse eines laufenden Server mit dem der Kontakt verbunden ist. 
   KEIN KONTO, KEIN PASSWORT, KEINE REGISTRIERUNG.

 - **NICHTS ZU INSTALLIEREN**: Du kannst es auf jeder Plattform benutzen, ohne ein Plugin oder eine Software installieren zu müssen (viele Personen haben nicht die System-Berechtigungen, um Änderungen am System durchzuführen) 

   => Cyptweet funktioniert (oder sollte, letztendlich) 
   auf (fast) jeder Plattform mit einem aktuellen Browser. Zögere nicht, alle Browser-Versionen zu melden, mit denen es nicht wie erwartet funktioniert.

 - **END-TO-END VERSCHLÜSSELUNG**: Der Server ist blind, er weiß nie, wer gerade mit wem spricht und was gerade gesagt wird, und das kann man leicht überprüfen. 

   => Der Cryptweet Server erhält nur verschlüsselte Pakete und sendet alles zu jedem zurück (so etwas wie Bitmessage). Nur die Person, die den privaten Schlüssel hat, kann das Paket entschlüsseln, und es macht es sehr schwierig für jemanden, die Kommunikation zu beobachten (auch bekannt als Traffic-Shaping)


## Wie es funktioniert

### DER SERVER 
 - Sollte auf HTTPS gehostet werden, mit einem gültigen Zertifikat, um eine vertrauenswürdige Verbindung zum Code des Clienten herzustellen (man vermeidet ein Man-in-the-Middle, der den Code des Clienten ändern könnte) 
 - Erzeugt eine neue Sitzung mit privatem Schlüssel beim Start 
 - Wartet auf Verbindungen Richtet ein RSA-getunneltes Socket ein mit jedem Clienten, der ein verschlüsseltes gültiges Paket mit einem gültigen öffentlichen RSA-Schlüssel anbietet.
 - Empfängt Pakete, die mit seinem öffentlichen Schlüssel verschlüsselt sind
 - Sendet jedes entschlüsselte Paket an jeden Clienten, nachdem er es wieder mit dem öffentlichen Schlüssel des Clienten (Broadcast) verschlüsselt hat
 - ToDo: Plugin für das Speichern von Offline-Nachrichten, mit Verwendung eines permanenten extra-privaten Schlüssel, der vom Plugin verwaltet wird. 


### DER CLIENT 
- Verwaltet die Kontakte und Gespräche 
- Ladet oder generiert den privaten Schlüssel des Benutzers 
- Sendet den öffentlichen Schlüssel des Benutzers zu dem Server,
  nachdem er ihn mit dem öffentlichen Schlüssel des Servers verschlüsselt hat 
- Wenn der Benutzer einen gültigen öffentlichen Kontaktschlüssel erstellt, initiiert der Client ein neues Gespräch mit diesem Kontakt, das heißt 
  1 . Verschlüsseln des öffentlichen Schlüssels des Benutzers 
      mit dem öffentlichen Schlüssel des Kontakts 
  2 . Verschlüsseln des Kontakt-verschlüsselten Pakets mit dem öffentlichen 
      Schlüssel des Servers 
  3 . Senden von diesem doppelt verschlüsselten Paket an den Server 
  4 . Auf der Server-Seite wird das Paket entschlüsselt und "broadcrypted" 
      zu allen aktuellen Sockets mit ihrer eigenen Crypto, einschließlich der, 
      der das Paket sendet 
- Wenn der Kontakt das Paket empfängt und entschlüsseln kann, wird er mit dem gleichen Mechanismus antworten als für die Aufnahme des öffentlichen Schlüssels (ACK_PUK_RECEIVED). 
- Der Benutzer, der die Verbindung initiiert, antwortet dann, dass er den ACK bekommen hat 
- ToDo: nach diesem Handschake, sollten die Kunden einen gemeinsamen symmetrischen Schlüssel für dieses Gespräch vereinbaren und sich auf ein Zeitlimit für die Verwendung des nächsten Schlüssel einigen. (vielleicht den alten Schlüssel für eine Weile behalten, falls ein Paket verloren geht) 
- Wenn Benutzer in einem Gespräch sind, haben sie die Möglichkeit, andere Kontakte zu dem Gespräch einzuladen, durch Hinzufügen des öffentlichen Schlüssel des Kontaktes zum Gespräch. 
- ToDo: Plugin für offline-Nachrichten 
- ToDo: Plugin für Dateiaustausch 

