'use strict';

/**
 * CipherLink relay server.
 *
 * The server is a TCP relay only. It holds no keys and does no
 * cryptography: it cannot read, sign or alter the handshake. For
 * HELLO / KEY_EXCHANGE / KEY_EXCHANGE_ACK it only
 *   - validates the message structure,
 *   - checks `sender` is this connection's assigned identity and (for
 *     KEY_EXCHANGE/ACK) that `recipient` is the other client,
 *   - forwards the ORIGINAL line byte-for-byte.
 * CHAT is still plaintext in this phase and is relayed as before.
 */

const net = require('net');
const {
  LineBuffer,
  encode,
  decode,
  MESSAGE_TYPES,
  HANDSHAKE_TYPES,
  PEER_EVENTS,
  MAX_FRAME_SIZE,
  FrameTooLargeError,
  createChatMessage,
  createSystemMessage,
  createPeerEventMessage,
  createErrorMessage,
  validateMessage,
} = require('./protocol/message');

const PORT = Number(process.env.CIPHERLINK_PORT || process.argv[2] || 5000);
// Loopback by default: this is a course project, not a hardened public service.
// Set CIPHERLINK_HOST=0.0.0.0 to accept connections from other machines.
const HOST = process.env.CIPHERLINK_HOST || '127.0.0.1';
const SLOTS = ['Client A', 'Client B'];

// slotId -> socket | null
const clients = { 'Client A': null, 'Client B': null };

function log(...args) {
  console.log(`[${new Date().toISOString()}]`, ...args);
}

function otherSlot(id) {
  return id === 'Client A' ? 'Client B' : 'Client A';
}

function freeSlot() {
  return SLOTS.find((id) => clients[id] === null) || null;
}

function writeTo(socket, text) {
  if (!socket || socket.destroyed) return;
  try {
    socket.write(text);
  } catch (err) {
    log('Failed to write to socket:', err.message);
  }
}

function send(socket, messageObj) {
  writeTo(socket, encode(messageObj));
}

const server = net.createServer((socket) => {
  const remote = `${socket.remoteAddress}:${socket.remotePort}`;
  const id = freeSlot();

  if (!id) {
    log(`Rejected connection from ${remote}: server already has two clients.`);
    send(socket, createErrorMessage('CipherLink server already has two clients connected. Try again later.'));
    socket.end();
    return;
  }

  clients[id] = socket;
  const buffer = new LineBuffer();
  log(`${id} connected from ${remote}`);
  send(socket, createSystemMessage(`Connected as ${id}`));

  const peerId = otherSlot(id);
  if (clients[peerId]) {
    // Both sides learn the pair is complete; each client then sends its HELLO.
    send(clients[peerId], createPeerEventMessage(PEER_EVENTS.PEER_JOINED, id, `${id} has joined the chat.`));
    send(socket, createPeerEventMessage(PEER_EVENTS.PEER_JOINED, peerId, `${peerId} is already connected.`));
  }

  let closing = false;

  socket.on('data', (chunk) => {
    if (closing) return; // draining a connection we are already closing: discard, never buffer

    let lines;
    try {
      lines = buffer.append(chunk.toString('utf8'));
    } catch (err) {
      if (!(err instanceof FrameTooLargeError)) throw err;
      closing = true;
      log(`${id} sent a frame larger than ${MAX_FRAME_SIZE} bytes; closing its connection.`);
      socket.end(encode(createErrorMessage(`Frame exceeds the maximum size of ${MAX_FRAME_SIZE} bytes. Closing connection.`)));
      // Give the error a moment to reach the peer, then drop the socket even if it keeps sending.
      setTimeout(() => socket.destroy(), 500).unref();
      return;
    }

    for (const line of lines) {
      if (line.trim() === '') {
        continue; // ignore empty messages
      }

      let msg;
      try {
        msg = decode(line);
      } catch (err) {
        log(`Malformed JSON from ${id}: ${err.message}`);
        send(socket, createErrorMessage('Malformed message ignored (invalid JSON).'));
        continue;
      }

      const validation = validateMessage(msg);
      if (!validation.valid) {
        log(`Invalid message from ${id}: ${validation.reason}`);
        send(socket, createErrorMessage(validation.reason));
        continue;
      }

      if (HANDSHAKE_TYPES.includes(msg.type)) {
        // The connection identity is assigned by the server; a client cannot claim another.
        if (msg.sender !== id) {
          log(`Rejected ${msg.type} from ${id}: sender does not match the connection identity.`);
          send(socket, createErrorMessage(`${msg.type} sender does not match your connection identity.`));
          continue;
        }
        if (msg.type !== MESSAGE_TYPES.HELLO && msg.recipient !== peerId) {
          log(`Rejected ${msg.type} from ${id}: recipient is not ${peerId}.`);
          send(socket, createErrorMessage(`${msg.type} recipient must be ${peerId}.`));
          continue;
        }

        // Only the message type is logged: handshake contents are never printed.
        log(`${id} -> ${peerId}: ${msg.type}`);
        const peerSocket = clients[peerId];
        if (peerSocket) {
          writeTo(peerSocket, line + '\n'); // original bytes, unmodified
        } else {
          send(socket, createSystemMessage(`${peerId} is not connected. Message not delivered.`));
        }
        continue;
      }

      if (msg.type !== MESSAGE_TYPES.CHAT) {
        send(socket, createErrorMessage(`Server does not accept "${msg.type}" messages from clients.`));
        continue;
      }

      // CHAT is unsigned plaintext in this phase: the server stamps the
      // sender itself rather than trusting whatever the client sent.
      const chatMessage = createChatMessage(id, msg.text);
      log(`${id} -> ${peerId}: ${msg.text}`);

      const peerSocket = clients[peerId];
      if (peerSocket) {
        send(peerSocket, chatMessage);
      } else {
        send(socket, createSystemMessage(`${peerId} is not connected. Message not delivered.`));
      }
    }
  });

  socket.on('close', () => {
    log(`${id} disconnected`);
    clients[id] = null;
    if (clients[peerId]) {
      send(clients[peerId], createPeerEventMessage(PEER_EVENTS.PEER_LEFT, id, `${id} has disconnected.`));
    }
  });

  socket.on('error', (err) => {
    log(`Socket error on ${id}: ${err.message}`);
  });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Is another CipherLink server running?`);
    console.error(`Stop it, or choose another port: npm run server -- ${PORT + 1}`);
  } else {
    log('Server error:', err.message);
  }
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log('CipherLink Server');
  console.log(`Listening on ${HOST}:${PORT}`);
  console.log('Waiting for clients...');
});

function shutdown() {
  log('Shutting down server...');
  for (const id of SLOTS) {
    if (clients[id]) {
      send(clients[id], createSystemMessage('Server is shutting down.'));
      clients[id].end();
    }
  }
  server.close(() => process.exit(0));
  // Fallback in case some socket keeps the event loop alive.
  setTimeout(() => process.exit(0), 1000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
