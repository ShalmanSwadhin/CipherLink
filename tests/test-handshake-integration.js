'use strict';

/**
 * Phase 4 integration tests. The real server runs as a child process.
 *
 *   Part 1: two raw-socket peers that use the real PeerSession. Because the
 *           test owns both sockets it can see every byte the server ever
 *           receives, so it can prove the server never sees a session key
 *           or a private key, and that handshake messages are relayed
 *           verbatim.
 *   Part 2: two real CLI clients (src/client.js) driven through stdin/stdout:
 *           same session-key fingerprint on both sides, plaintext chat intact.
 *
 * Run with: npm test
 */

const net = require('net');
const path = require('path');
const assert = require('assert');
const { spawn } = require('child_process');
const {
  LineBuffer,
  encode,
  decode,
  MESSAGE_TYPES,
  HANDSHAKE_TYPES,
  PEER_EVENTS,
  createChatMessage,
  createHelloMessage,
} = require('../src/protocol/message');
const { createIdentity, exportPublicKeys } = require('../src/security/identity');
const { PeerSession, SESSION_STATES } = require('../src/security/peer-session');
const { createKeyExchange } = require('../src/security/handshake');
const { exportPrivateKey } = require('../src/crypto/keys');

const ROOT = path.join(__dirname, '..');
const SERVER_PATH = path.join(ROOT, 'src', 'server.js');
const CLIENT_PATH = path.join(ROOT, 'src', 'client.js');
const RAW_PORT = 5199;
const CLI_PORT = 5299;

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  PASS - ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL - ${name}`);
    console.log(`         ${err.message}`);
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(condition, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) return;
    await delay(20);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

function startServer(port) {
  const proc = spawn(process.execPath, [SERVER_PATH, String(port)], { stdio: 'pipe' });
  const server = { proc, output: '' };
  proc.stdout.on('data', (d) => { server.output += d.toString(); });
  proc.stderr.on('data', (d) => { server.output += d.toString(); });
  return server;
}

/** A raw-socket client driven by the real PeerSession (the same logic src/client.js uses). */
class RawPeer {
  constructor(port, identity) {
    this.identity = identity;
    this.selfId = null;
    this.session = null;
    this.messages = []; // every decoded message received
    this.receivedLines = []; // raw lines exactly as received
    this.sentLines = []; // raw lines exactly as sent (what the server receives)
    this.sessionErrors = [];
    this.buffer = new LineBuffer();
    this.socket = net.createConnection({ host: 'localhost', port });
    this.socket.on('data', (chunk) => this._onData(chunk));
    this.socket.on('error', () => {});
  }

  _onData(chunk) {
    for (const line of this.buffer.append(chunk.toString('utf8'))) {
      if (line.trim() === '') continue;
      this.receivedLines.push(line);
      const msg = decode(line);
      this.messages.push(msg);
      this._dispatch(msg);
    }
  }

  _dispatch(msg) {
    if (msg.type === MESSAGE_TYPES.SYSTEM) {
      if (msg.text.startsWith('Connected as ')) {
        this.selfId = msg.text.slice('Connected as '.length);
        this.session = new PeerSession({ selfId: this.selfId, identity: this.identity });
      } else if (msg.event === PEER_EVENTS.PEER_JOINED) {
        this._apply(this.session.onPeerJoined());
      } else if (msg.event === PEER_EVENTS.PEER_LEFT) {
        this.session.onPeerLeft();
      }
    } else if (HANDSHAKE_TYPES.includes(msg.type)) {
      this._apply(this.session.handleMessage(msg));
    }
  }

  _apply(result) {
    if (result.error) this.sessionErrors.push(result.error);
    for (const out of result.outgoing) this.send(out);
  }

  send(msg) {
    const line = encode(msg);
    this.sentLines.push(line.slice(0, -1));
    this.socket.write(line);
  }

  sendLine(line) {
    this.sentLines.push(line);
    this.socket.write(line + '\n');
  }

  get established() {
    return this.session !== null && this.session.state === SESSION_STATES.ESTABLISHED;
  }

  ofType(type) {
    return this.messages.filter((m) => m.type === type);
  }

  close() {
    this.socket.destroy();
  }
}

function spawnCli(port) {
  const proc = spawn(process.execPath, [CLIENT_PATH, String(port)], { stdio: ['pipe', 'pipe', 'pipe'] });
  const cli = { proc, out: '' };
  proc.stdout.on('data', (d) => { cli.out += d.toString(); });
  proc.stderr.on('data', (d) => { cli.out += d.toString(); });
  return cli;
}

function base64Forms(buf) {
  return [buf.toString('hex'), buf.toString('base64'), buf.toString('base64url'), buf.toString('latin1')];
}

async function main() {
  console.log('Running Phase 4 integration tests (real server + real clients)...');
  const identityA = createIdentity();
  const identityB = createIdentity();
  const server = startServer(RAW_PORT);
  const cliServer = startServer(CLI_PORT);
  const cleanup = [];

  await test('Integration 1: the real server starts', async () => {
    await until(() => server.output.includes('Waiting for clients') && cliServer.output.includes('Waiting for clients'), 5000, 'servers to listen');
  });

  let peerA;
  let peerB;

  await test('Integration 2: HELLO, KEY_EXCHANGE and ACK complete; both sides are ESTABLISHED with the same key', async () => {
    peerA = new RawPeer(RAW_PORT, identityA);
    await until(() => peerA.selfId === 'Client A', 3000, 'A to be assigned identity');
    peerB = new RawPeer(RAW_PORT, identityB);
    await until(() => peerA.established && peerB.established, 10000, 'both sessions to be ESTABLISHED');
    cleanup.push(peerA, peerB);

    assert.strictEqual(peerB.selfId, 'Client B');
    assert.strictEqual(peerA.session.sessionId, peerB.session.sessionId);
    assert.ok(peerA.session.sessionKey.equals(peerB.session.sessionKey), 'both sides hold the identical session key');
    assert.strictEqual(peerA.session.sessionKey.length, 32);
    assert.strictEqual(peerA.session.sessionKeyFingerprint(), peerB.session.sessionKeyFingerprint());
    assert.deepStrictEqual(peerA.sessionErrors, []);
    assert.deepStrictEqual(peerB.sessionErrors, []);
  });

  await test('Integration 3: the handshake messages are relayed in order through the server', async () => {
    const handshakeTypes = (peer) => peer.messages.filter((m) => HANDSHAKE_TYPES.includes(m.type)).map((m) => m.type);
    assert.deepStrictEqual(handshakeTypes(peerA), ['HELLO', 'KEY_EXCHANGE_ACK']);
    assert.deepStrictEqual(handshakeTypes(peerB), ['HELLO', 'KEY_EXCHANGE']);
  });

  await test('Integration 4: the server relays handshake messages verbatim (byte-for-byte)', async () => {
    const lineOf = (lines, type) => lines.find((l) => decode(l).type === type);
    assert.strictEqual(lineOf(peerB.receivedLines, 'KEY_EXCHANGE'), lineOf(peerA.sentLines, 'KEY_EXCHANGE'));
    assert.strictEqual(lineOf(peerB.receivedLines, 'HELLO'), lineOf(peerA.sentLines, 'HELLO'));
    assert.strictEqual(lineOf(peerA.receivedLines, 'HELLO'), lineOf(peerB.sentLines, 'HELLO'));
    assert.strictEqual(lineOf(peerA.receivedLines, 'KEY_EXCHANGE_ACK'), lineOf(peerB.sentLines, 'KEY_EXCHANGE_ACK'));
  });

  await test('Integration 5: the server never receives the plaintext session key or any private key', async () => {
    const serverSaw = [...peerA.sentLines, ...peerB.sentLines, server.output].join('\n');
    for (const form of base64Forms(peerA.session.sessionKey)) {
      assert.ok(!serverSaw.includes(form), 'session key must not reach the server in any encoding');
    }
    for (const identity of [identityA, identityB]) {
      for (const pair of [identity.encryption, identity.signing]) {
        for (const line of exportPrivateKey(pair.privateKey).trim().split('\n').slice(1, -1)) {
          assert.ok(!serverSaw.includes(line), 'private key material must not reach the server');
        }
      }
    }
    assert.ok(!/BEGIN (RSA )?PRIVATE KEY/.test(serverSaw));
    // The server logs only message types for handshake traffic, never their contents.
    assert.ok(/Client A -> Client B: KEY_EXCHANGE/.test(server.output));
    assert.ok(!server.output.includes(peerA.session.sessionId), 'handshake fields are not logged');
  });

  await test('Integration 6: ordinary CHAT is still plaintext and works both ways', async () => {
    peerA.send(createChatMessage('Client A', 'Hello Bob'));
    await until(() => peerB.ofType('CHAT').length === 1, 3000, 'Bob to receive Hello Bob');
    peerB.send(createChatMessage('Client B', 'Hi Alice'));
    await until(() => peerA.ofType('CHAT').length === 1, 3000, 'Alice to receive Hi Alice');

    assert.deepStrictEqual(peerB.ofType('CHAT')[0], { type: 'CHAT', version: 1, sender: 'Client A', text: 'Hello Bob' });
    assert.deepStrictEqual(peerA.ofType('CHAT')[0], { type: 'CHAT', version: 1, sender: 'Client B', text: 'Hi Alice' });
    // No encrypted-chat fields exist on the wire yet.
    for (const field of ['ciphertext', 'nonce', 'authTag', 'sequence', 'timestamp']) {
      assert.ok(!(field in peerB.ofType('CHAT')[0]));
    }
  });

  await test('Integration 7: the server rejects a handshake message whose sender is not the connection identity', async () => {
    const before = peerB.messages.length;
    const pemsB = exportPublicKeys(identityB);
    peerA.send(createHelloMessage('Client B', pemsB.encryptionPublicKey, pemsB.signingPublicKey)); // A claims to be B
    await until(() => peerA.ofType('ERROR').length >= 1, 3000, 'ERROR for forged HELLO sender');
    assert.ok(/sender does not match/.test(peerA.ofType('ERROR').at(-1).text));

    const forgedAck = { type: 'KEY_EXCHANGE_ACK', version: 1, sender: 'Client B', recipient: 'Client A', sessionId: 'a'.repeat(32), signature: 'A'.repeat(512) };
    peerA.send(forgedAck);
    await until(() => peerA.ofType('ERROR').length >= 2, 3000, 'ERROR for forged ACK sender');

    peerA.send(createChatMessage('Client A', 'sentinel-1'));
    await until(() => peerB.ofType('CHAT').some((m) => m.text === 'sentinel-1'), 3000, 'sentinel chat');
    const relayed = peerB.messages.slice(before);
    assert.ok(!relayed.some((m) => HANDSHAKE_TYPES.includes(m.type)), 'forged handshake messages must not be forwarded');
  });

  await test('Integration 8: the server rejects a KEY_EXCHANGE addressed to someone other than the peer', async () => {
    const before = peerB.messages.length;
    const misaddressed = createKeyExchange({
      sender: 'Client A',
      recipient: 'Client C',
      signingPrivateKey: identityA.signing.privateKey,
      peerEncryptionPublicKey: identityB.encryption.publicKey,
    }).message;
    peerA.send(misaddressed);
    await until(() => peerA.ofType('ERROR').some((m) => /recipient must be Client B/.test(m.text)), 3000, 'recipient ERROR');

    peerA.send(createChatMessage('Client A', 'sentinel-2'));
    await until(() => peerB.ofType('CHAT').some((m) => m.text === 'sentinel-2'), 3000, 'sentinel chat');
    assert.ok(!peerB.messages.slice(before).some((m) => m.type === 'KEY_EXCHANGE'));
  });

  await test('Integration 9: the server rejects key-less HELLOs and HELLOs carrying private keys, and keeps running', async () => {
    const before = peerB.messages.length;
    const errorsBefore = peerA.ofType('ERROR').length;
    peerA.sendLine(JSON.stringify({ type: 'HELLO', version: 1, sender: 'Client A' }));
    const pemsA = exportPublicKeys(identityA);
    peerA.sendLine(JSON.stringify({
      ...createHelloMessage('Client A', pemsA.encryptionPublicKey, pemsA.signingPublicKey),
      encryptionPrivateKey: exportPrivateKey(identityA.encryption.privateKey),
    }));
    peerA.sendLine(JSON.stringify({ ...createHelloMessage('Client A', pemsA.encryptionPublicKey, pemsA.signingPublicKey), version: 999 }));
    await until(() => peerA.ofType('ERROR').length >= errorsBefore + 3, 3000, 'three ERROR replies');
    const texts = peerA.ofType('ERROR').slice(errorsBefore).map((m) => m.text);
    assert.ok(/encryptionPublicKey/.test(texts[0]));
    assert.ok(/private key/i.test(texts[1]));
    assert.ok(/version/i.test(texts[2]));
    assert.ok(!texts.join('\n').includes('BEGIN'), 'error replies must not echo key material');

    peerA.send(createChatMessage('Client A', 'sentinel-3'));
    await until(() => peerB.ofType('CHAT').some((m) => m.text === 'sentinel-3'), 3000, 'sentinel chat');
    assert.ok(!peerB.messages.slice(before).some((m) => HANDSHAKE_TYPES.includes(m.type)));
  });

  await test('Integration 10: a replayed KEY_EXCHANGE does not disturb the established session', async () => {
    const keyBefore = Buffer.from(peerB.session.sessionKey);
    const idBefore = peerB.session.sessionId;
    const keyExchangeLine = peerA.sentLines.find((l) => decode(l).type === 'KEY_EXCHANGE');
    const errorsBefore = peerB.sessionErrors.length;

    peerA.sendLine(keyExchangeLine); // the server relays it; B must refuse to re-establish
    await until(() => peerB.sessionErrors.length > errorsBefore, 3000, 'B to reject the duplicate');
    assert.ok(/already established/.test(peerB.sessionErrors.at(-1)));
    assert.strictEqual(peerB.session.state, SESSION_STATES.ESTABLISHED);
    assert.ok(peerB.session.sessionKey.equals(keyBefore));
    assert.strictEqual(peerB.session.sessionId, idBefore);
    assert.strictEqual(peerA.session.sessionKeyFingerprint(), peerB.session.sessionKeyFingerprint());
  });

  await test('Integration 11: after the peer leaves and a new peer joins, a fresh session is established', async () => {
    const oldFingerprint = peerA.session.sessionKeyFingerprint();
    const oldSessionId = peerA.session.sessionId;

    peerB.close();
    await until(() => peerA.session.state === SESSION_STATES.NO_SESSION, 3000, 'A to clear its session after the peer left');
    assert.strictEqual(peerA.session.sessionKey, null);

    const peerB2 = new RawPeer(RAW_PORT, createIdentity()); // a new client with brand-new keys
    cleanup.push(peerB2);
    await until(() => peerA.established && peerB2.established, 10000, 'the new session to be ESTABLISHED');
    assert.strictEqual(peerB2.selfId, 'Client B');
    assert.notStrictEqual(peerA.session.sessionId, oldSessionId);
    assert.notStrictEqual(peerA.session.sessionKeyFingerprint(), oldFingerprint);
    assert.strictEqual(peerA.session.sessionKeyFingerprint(), peerB2.session.sessionKeyFingerprint());
    assert.ok(peerA.session.sessionKey.equals(peerB2.session.sessionKey));
  });

  // ---- Part 2: the real CLI clients ---------------------------------------
  await test('Integration 12: two real CLI clients establish a session, print matching fingerprints, and chat in plaintext', async () => {
    const cliA = spawnCli(CLI_PORT);
    cleanup.push({ close: () => cliA.proc.kill() });
    await until(() => cliA.out.includes('Identity: Client A'), 30000, 'CLI A to connect');
    const cliB = spawnCli(CLI_PORT);
    cleanup.push({ close: () => cliB.proc.kill() });
    await until(() => cliA.out.includes('[SESSION] Established') && cliB.out.includes('[SESSION] Established'), 30000, 'both CLIs to report an established session');

    const fingerprintOf = (out) => (out.match(/Key fingerprint \(diagnostic only\): ([0-9a-f]{8}\.\.\.[0-9a-f]{8})/) || [])[1];
    const sessionIdOf = (out) => (out.match(/ID: ([0-9a-f]{32})/) || [])[1];
    assert.ok(fingerprintOf(cliA.out), 'A prints a fingerprint');
    assert.strictEqual(fingerprintOf(cliA.out), fingerprintOf(cliB.out), 'both CLIs report the same session-key fingerprint');
    assert.strictEqual(sessionIdOf(cliA.out), sessionIdOf(cliB.out));
    assert.ok(/Chat is still plaintext/.test(cliA.out));

    // Neither CLI may print a raw key (64 hex chars) or any private key.
    for (const out of [cliA.out, cliB.out]) {
      assert.ok(!/[0-9a-f]{64}/.test(out), 'no raw 256-bit value may be printed');
      assert.ok(!/PRIVATE KEY/.test(out));
    }

    cliA.proc.stdin.write('Hello Bob\n');
    await until(() => cliB.out.includes('Client A: Hello Bob'), 5000, 'B to receive Hello Bob');
    cliB.proc.stdin.write('Hi Alice\n');
    await until(() => cliA.out.includes('Client B: Hi Alice'), 5000, 'A to receive Hi Alice');
  });

  for (const item of cleanup) item.close();
  server.proc.kill();
  cliServer.proc.kill();

  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('Integration test runner crashed:', err);
  process.exit(1);
});
