/* Copyright (c) 2016 Pablo Rodiz, Sameh Hady, Gordon Williams. See the file LICENSE for copying permission. */
/*
 Simple WebSocket protocol wrapper for Espruino sockets.
 * KEYWORDS: Module,websocket,wss,socket,secure
 Websocket implementation on Espruino, it let you control your Espruino from the cloud without the need to know it's IP.
 You will need to use it with a websocket server.
 Implementation for plain and encrypted WebSockets. For using secure Websockets over SSL just include ca, key and 
 certificate information in the options structure.
 Limitations: The module only accept messages less than 127 character.
 How to use the wss module:
 ```javascript
 // Connect to WiFi, then...
 // =============================== CLIENT
 var WebSocket = require("wss");
 var wss = new WebSocket("HOST",{
      port: 8080,
      protocolVersion: 13,
      origin: 'Espruino',
      keepAlive: 60  // Ping Interval in seconds.
    });
 wss.on('open', function() {
   console.log("Connected to server");
 });
 wss.on('message', function(msg) {
   console.log("MSG: " + msg);
 });
 wss.on('close', function() {
   console.log("Connection closed");
 });
 
 //Send message to server
 wss.send("Hello Server");
 
 // =============================== SECURE CLIENT
 //See this thread http://forum.espruino.com/conversations/277780/?offset=50 on how to create and use the certificates
 var WebSocket = require("wss");
 var wss = new WebSocket("HOST",{
      port: 8080,
      protocolVersion: 13,
      origin: 'Espruino',
      keepAlive: 60,  // Ping Interval in seconds.
      key :  okey,
      ca :   oca,
      cert : ocert
    });
 wss.on('open', function() {
   console.log("Connected to server");
 });
 wss.on('message', function(msg) {
   console.log("MSG: " + msg);
 });
 wss.on('close', function() {
   console.log("Connection closed");
 });
 
 //Send message to server
 wss.send("Hello Server");
 
 
 
 // =============================== SERVER
 var page = '<html><body><script>var ws;setTimeout(function(){';
 page += 'ws = new WebSocket("ws://" + location.host + "/my_websocket", "protocolOne");';
 page += 'ws.onmessage = function (event) { console.log("MSG:"+event.data); };';
 page += 'setTimeout(function() { ws.send("Hello to Espruino!"); }, 1000);';
 page += '},1000);</script></body></html>';
 function onPageRequest(req, res) {
  res.writeHead(200, {'Content-Type': 'text/html'});
  res.end(page);
 }
 var server = require('ws').createServer(onPageRequest);
 server.listen(8000);
 server.on("websocket", function(ws) {
    ws.on('message',function(msg) { print("[WS] "+JSON.stringify(msg)); });
    ws.send("Hello from Espruino!");
 });
 // =============================== SECURE SERVER
 // There is no implementation yet available for https server, so I think it is not yet possible to 
 //create a secure websocket implementation... at least easily :)  
```
*/

/** Minify String.fromCharCode() call */
var strChr = String.fromCharCode;

function WebSocket(host, options) {
    this.socket = null;
    options = options || {};
    this.host = host;
    this.port = options.port || 80;
    this.protocolVersion = options.protocolVersion || 13;
    this.origin = options.origin || 'Espruino';
    this.keepAlive = options.keepAlive * 1000 || 60000;
    this.key = options.key;
    this.ca = options.ca;
    this.cert = options.cert;
    this.websocketKey = btoa(Array(16+1).join(((E.hwRand()*E.hwRand()*E.hwRand()).toString(36)+'00000000000000000').slice(2, 18)).slice(0, 16));
}

WebSocket.prototype.initializeConnection = function () {
    if(typeof this.key !== 'undefined' && typeof this.ca !== 'undefined' && typeof this.cert !== 'undefined') {  
      require("tls").connect({
        host:  this.host,
        port:  this.port,
        key :  this.key,
        ca :   this.ca,
        cert : this.cert,
      }, this.onConnect.bind(this));
    } else {
      require("net").connect({
        host:  this.host,
        port:  this.port,
      }, this.onConnect.bind(this));
    }  
};

WebSocket.prototype.onConnect = function (socket) {
    this.socket = socket;
  
    var ws = this;
    this.socket.on('data', function(data) { 
      try {
	ws.parseData(data);
      } catch (e) {
	console.log(e);
	//We need to exit ths function before ending the socket or the execution will stop
	setTimeout(function() {ws.socket.end();}, 0);
      }
    });
	
    this.socket.on('close', function () {
        ws.emit('close');
    });
  
    this.socket.on('error', function (err) {
      console.log('Socket error');
      console.log(err);
    });  
	
    this.emit('open');
    this.handshake();
};

WebSocket.prototype.parseData = function (data) {
    // see https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    // Note, docs specify bits 0-7, etc - but BIT 0 is the MSB, 7 is the LSB
    // TODO: handle >1 data packet, or packets split over multiple parseData calls
    var ws = this;
    this.emit('rawData', data);
    if (data.indexOf('HTTP/1.1') > -1) {  
      if (data.indexOf('101 Switching Protocols') > -1 && data.indexOf(btoa(require("crypto").SHA1(this.websocketKey+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'))) > -1) {
        this.emit('handshake');
        var ping = setInterval(function () {
            ws.send('ping', 0x89);
        }, this.keepAlive);
      } else {
	// Handshake answer from the server was not correct
	//ws.socket.end();
	// We can not finish the socket while executing parseData callback or program 
	//will break when returning. We fire an exception to ask the parent function to close the socket instead  
        throw "Handshake error";
      }  
    } else {

      var opcode = data.charCodeAt(0)&15;

      if (opcode == 0xA) {
        this.emit('pong');
		return;  
	  }
      if (opcode == 0x9) {
        this.send('pong', 0x8A);
        this.emit('ping');
		return;
      }

      if (opcode == 0x8) {
          // connection close request
	  //ws.socket.end();
	  // We can not finish the socket while executing parseData callback or program 
	  //will break when returning. We fire an exception to ask the parent function to close the socket instead  
          // we'll emit a 'close' when the socket itself closes
	  throw "Request to close connection";
      }

      if (opcode == 1 /* text - all we're supporting */) {
          var dataLen = data.charCodeAt(1)&127;
          if (dataLen>126) throw "Messages >125 in length unsupported";
          var offset = 2;
          var mask = [ 0,0,0,0 ];
          if (data.charCodeAt(1)&128 /* mask */)
          mask = [ data.charCodeAt(offset++), data.charCodeAt(offset++),
              data.charCodeAt(offset++), data.charCodeAt(offset++)];

          var message = "";
          for (var i = 0; i < dataLen; i++) {
              message += String.fromCharCode(data.charCodeAt(offset++) ^ mask[i&3]);
          }
          this.emit('message', message);
      }
   } 
};

WebSocket.prototype.handshake = function () {
   var socketHeader = [
      "GET / HTTP/1.1",
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Key: " + this.websocketKey,
      "Sec-WebSocket-Version: " + this.protocolVersion,
      "Sec-WebSocket-Protocol: echo-protocol",
      "Origin: " + this.origin,
      "Host: " + this.host,
      "",""
   ];

   this.socket.write(socketHeader.join("\r\n"));
};

WebSocket.prototype.close = function () {
    this.socket.write(strChr(0x88)+strChr(0x02)+strChr(0x10)+strChr(0x00));
};

/** Send message based on opcode type */
WebSocket.prototype.send = function (msg, opcode) {
    opcode = opcode === undefined ? 0x81 : opcode;
    this.socket.write(strChr(opcode, msg.length));
    this.socket.write(msg);
};

/** Create a WebSocket client */
exports = function (host, options) {
    var ws = new WebSocket(host, options);
    ws.initializeConnection();
    return ws;
};

/** Create a WebSocket server */
exports.createServer = function(callback, wscallback) {
  var server = require('http').createServer(function (req, res) {
    if (req.headers.Connection=="Upgrade") {    
      var key = req.headers["Sec-WebSocket-Key"];
      var accept = btoa(E.toString(require("crypto").SHA1(key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
      res.writeHead(101, {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade',
          'Sec-WebSocket-Accept': accept,
          'Sec-WebSocket-Protocol': req.headers["Sec-WebSocket-Protocol"]
      });
      res.write(""); /** Completes the webSocket handshake on pre-1v85 builds **/

      var ws = new WebSocket(undefined, {});
      ws.socket = res;
      req.on('data', ws.parseData.bind(ws) );
      req.on('close', function() {
        // if srvPing is undefined, we already emitted a 'close'
        clearInterval(ws.srvPing);
        ws.srvPing = undefined;
        // emit websocket close event
        ws.emit('close');
      });
      /** Start a server ping at the keepAlive interval  **/
      ws.srvPing = setInterval(function () {
          ws.emit('ping', true); // true: indicates a server ping
          ws.send('ping', 0x89);
      }, ws.keepAlive);
      server.emit("websocket", ws);
    } else callback(req, res);
  });
  return server;
};
