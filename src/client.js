'use strict';

/**
 * CipherLink CLI client.
 *
 * Commands:  /status   show session status
 *            /help     list commands
 *            /quit     disconnect and exit (Ctrl+C / Ctrl+D also work)
 * Anything else you type is sent as a plaintext CHAT message (message
 * encryption is not implemented yet).
 *
 * Only safe diagnostics are printed: never private keys, the session key,
 * public-key PEMs or signatures.
 */

const net = require('net');
const readline = require('readline');
const {
  LineBuffer,
  FrameTooLargeError,
  MAX_FRAME_SIZE,
  encode,
  decode,
  MESSAGE_TYPES,
  HANDSHAKE_TYPES,
  PEER_EVENTS,
  createChatMessage,
  validateMessage,
} = require('./protocol/message');
const { createIdentity } = require('./security/identity');
const { PeerSession, SESSION_STATES } = require('./security/peer-session');

const PORT = Number(process.env.CIPHERLINK_PORT || process.argv[2] || 5000);
const HOST = process.env.CIPHERLINK_HOST || '127.0.0.1';

const isTTY = Boolean(process.stdout.isTTY);
const buffer = new LineBuffer();
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });

let myId = null;
let identity = null;
let session = null;
let peerPresent = false;
let closing = false;

// Messages wait here while the (synchronous, ~1s) key generation runs, so that
// "Generating identity keys..." is printed before the process blocks.
const queue = [];
let generatingKeys = false;

// ---- output ---------------------------------------------------------------

function showPrompt() {
  if (isTTY && !closing) rl.prompt(true);
}

/** Prints lines without clobbering the line being typed. */
function log(...lines) {
  if (isTTY) {
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
  }
  console.log(lines.join('\n'));
  showPrompt();
}

function sessionSummaryLines() {
  return [
    `[SESSION] Established with ${session.peerId}`,
    `[SESSION] ID: ${session.sessionId}`,
    `[SESSION] Key fingerprint (diagnostic only): ${session.sessionKeyFingerprint()}`,
    '[SESSION] Chat is still plaintext in this phase (message encryption is not implemented yet)',
  ];
}

function statusLines() {
  const established = session && session.state === SESSION_STATES.ESTABLISHED;
  return [
    'CipherLink Session Status',
    '',
    `Identity: ${myId || '(not assigned yet)'}`,
    `Peer: ${session ? session.peerId : '-'}${session ? (peerPresent ? ' (connected)' : ' (not connected)') : ''}`,
    `State: ${session ? session.state : generatingKeys ? 'GENERATING_KEYS' : 'NO_SESSION'}`,
    `Session ID: ${established ? session.sessionId : '-'}`,
    `Session key fingerprint: ${established ? session.sessionKeyFingerprint() : '-'}`,
  ];
}

function describeHandshake(msg, result) {
  const lines = [`[HANDSHAKE] ${msg.type} received from ${msg.sender}`];
  if (result.error) {
    lines.push(`[HANDSHAKE] ${msg.type} rejected: ${result.error}`);
    if (session.state === SESSION_STATES.FAILED) {
      lines.push('[SESSION] Handshake failed; no session established.');
    }
    return lines;
  }

  if (msg.type === MESSAGE_TYPES.HELLO) {
    lines.push('[HANDSHAKE] Peer public keys accepted');
    if (result.event === 'KEY_EXCHANGE_SENT') {
      lines.push('[HANDSHAKE] Generating session key');
    }
  } else if (result.event === 'ESTABLISHED') {
    lines.push('[HANDSHAKE] Signature verified');
    if (msg.type === MESSAGE_TYPES.KEY_EXCHANGE) {
      lines.push('[HANDSHAKE] Session key decrypted');
    }
  }
  for (const out of result.outgoing) {
    lines.push(`[HANDSHAKE] ${out.type} sent`);
  }
  if (result.event === 'ESTABLISHED') {
    lines.push(...sessionSummaryLines());
  }
  return lines;
}

// ---- networking -----------------------------------------------------------

function sendMessage(messageObj) {
  socket.write(encode(messageObj));
}

function shutdown(message) {
  if (closing) return;
  closing = true;
  console.log(message);
  socket.end();
  rl.close();
  setTimeout(() => process.exit(0), 300);
}

console.log(`Connecting to CipherLink server at ${HOST}:${PORT}...`);
const socket = net.createConnection({ host: HOST, port: PORT });

socket.on('data', (chunk) => {
  let lines;
  try {
    lines = buffer.append(chunk.toString('utf8'));
  } catch (err) {
    if (!(err instanceof FrameTooLargeError)) throw err;
    log(`[ERROR] The server sent a frame larger than ${MAX_FRAME_SIZE} bytes. Disconnecting.`);
    shutdown('Disconnected.');
    return;
  }
  for (const line of lines) {
    if (line.trim() === '') continue;
    let msg;
    try {
      msg = decode(line);
    } catch (err) {
      continue; // ignore malformed lines from the server
    }
    if (!validateMessage(msg).valid) {
      continue; // ignore structurally invalid frames from the server
    }
    queue.push(msg);
  }
  drain();
});

function drain() {
  while (queue.length > 0 && !generatingKeys) {
    handleMessage(queue.shift());
  }
}

function onIdentityAssigned(id) {
  myId = id;
  generatingKeys = true;
  log('Connected to CipherLink server', `Identity: ${id}`, 'Generating identity keys...');
  // Let the lines above reach the screen before the synchronous key generation blocks the process.
  setTimeout(() => {
    identity = createIdentity();
    session = new PeerSession({ selfId: id, identity });
    generatingKeys = false;
    const peerAlreadyHere = queue.some((m) => m.event === PEER_EVENTS.PEER_JOINED);
    log('Identity keys ready', ...(peerAlreadyHere ? [] : ['Waiting for peer... (HELLO is sent when the other client joins)']));
    drain();
  }, 20);
}

function handleMessage(msg) {
  switch (msg.type) {
    case MESSAGE_TYPES.SYSTEM:
      if (msg.text.startsWith('Connected as ')) {
        onIdentityAssigned(msg.text.slice('Connected as '.length));
      } else if (msg.event === PEER_EVENTS.PEER_JOINED) {
        peerPresent = true;
        const result = session.onPeerJoined();
        log(`[SYSTEM] ${msg.text}`, ...result.outgoing.map((m) => `[HANDSHAKE] ${m.type} sent`));
        for (const out of result.outgoing) sendMessage(out);
      } else if (msg.event === PEER_EVENTS.PEER_LEFT) {
        peerPresent = false;
        session.onPeerLeft();
        log(`[SYSTEM] ${msg.text}`, '[SESSION] Ended: the peer left, session state cleared. A new peer will trigger a new handshake.');
      } else {
        log(`[SYSTEM] ${msg.text}`);
      }
      break;
    case MESSAGE_TYPES.ERROR:
      log(`[ERROR] ${msg.text}`);
      break;
    case MESSAGE_TYPES.CHAT:
      log(`${msg.sender}: ${msg.text}`);
      break;
    default:
      if (HANDSHAKE_TYPES.includes(msg.type) && session) {
        const result = session.handleMessage(msg);
        for (const out of result.outgoing) sendMessage(out);
        log(...describeHandshake(msg, result));
      }
  }
}

// ---- user input -----------------------------------------------------------

function runCommand(text) {
  switch (text.toLowerCase()) {
    case '/status':
      log(...statusLines());
      break;
    case '/help':
      log('Commands:', '  /status  show identity, peer and session state', '  /quit    disconnect and exit', '  anything else is sent as a (plaintext) chat message');
      break;
    case '/quit':
    case '/exit':
      shutdown('Disconnecting...');
      break;
    default:
      log(`Unknown command "${text}". Type /help for the list of commands.`);
  }
}

rl.on('line', (line) => {
  const text = line.trim();
  if (text === '') {
    showPrompt();
    return;
  }
  if (text.startsWith('/')) {
    runCommand(text);
    return;
  }
  if (socket.destroyed || myId === null) {
    log('Not connected to the server.');
    return;
  }
  const encoded = encode(createChatMessage(myId, text));
  if (Buffer.byteLength(encoded, 'utf8') > MAX_FRAME_SIZE) {
    log(`[ERROR] Message too long (limit is ${MAX_FRAME_SIZE} bytes per message). Not sent.`);
    return;
  }
  socket.write(encoded);
  showPrompt();
});

rl.on('SIGINT', () => shutdown('\nDisconnecting...'));
rl.on('close', () => shutdown('Input closed. Disconnecting...'));

socket.on('close', () => {
  if (!closing) console.log('\nDisconnected from server.');
  process.exit(0);
});

socket.on('error', (err) => {
  if (err.code === 'ECONNREFUSED') {
    console.error(`Could not connect to ${HOST}:${PORT}. Is the server running? Start it with: npm run server`);
  } else {
    console.error(`Connection error: ${err.message}`);
  }
  process.exit(1);
});
