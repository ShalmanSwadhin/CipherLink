'use strict';

/**
 * Self-contained integration test for the CipherLink Phase 1 server.
 * No test framework/dependencies: spawns the real server as a child
 * process and drives it with raw net sockets so we can test framing
 * edge cases (split chunks, multiple messages per chunk) precisely.
 *
 * Run with: npm test
 */

const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
const assert = require('assert');
const { EventEmitter } = require('events');
const { LineBuffer, encode, decode, createChatMessage } = require('../src/protocol/message');

const PORT = 5099;
const HOST = 'localhost';
const SERVER_PATH = path.join(__dirname, '..', 'src', 'server.js');

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

function waitFor(emitter, predicate, timeoutMs, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      emitter.removeListener('message', onMessage);
      reject(new Error(`Timed out waiting for ${label || 'message'}`));
    }, timeoutMs);

    function onMessage(msg) {
      if (predicate(msg)) {
        clearTimeout(timer);
        emitter.removeListener('message', onMessage);
        resolve(msg);
      }
    }
    emitter.on('message', onMessage);
  });
}

function makeClient() {
  const emitter = new EventEmitter();
  const buffer = new LineBuffer();
  const socket = net.createConnection({ host: HOST, port: PORT });
  const received = [];

  socket.on('data', (chunk) => {
    const lines = buffer.append(chunk.toString('utf8'));
    for (const line of lines) {
      if (line.trim() === '') continue;
      let msg;
      try {
        msg = decode(line);
      } catch (err) {
        continue;
      }
      received.push(msg);
      emitter.emit('message', msg);
    }
  });

  emitter.socket = socket;
  emitter.received = received;
  emitter.rawWrite = (str) => socket.write(str);
  emitter.sendChat = (sender, text) => socket.write(encode(createChatMessage(sender, text)));
  emitter.waitConnected = () => new Promise((resolve, reject) => {
    socket.once('connect', resolve);
    socket.once('error', reject);
  });
  return emitter;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  console.log('Starting CipherLink server for tests...');
  const serverProcess = spawn(process.execPath, [SERVER_PATH, String(PORT)], { stdio: 'pipe' });

  let serverOutput = '';
  serverProcess.stdout.on('data', (d) => { serverOutput += d.toString(); });
  serverProcess.stderr.on('data', (d) => { serverOutput += d.toString(); });

  await test('Test 1: server starts and listens', async () => {
    const start = Date.now();
    while (!serverOutput.includes('Waiting for clients') && Date.now() - start < 3000) {
      await delay(50);
    }
    assert.ok(serverOutput.includes('Waiting for clients'), 'expected the server to print its startup banner');
  });

  let clientA;
  await test('Test 2: Client A connects and is assigned identity', async () => {
    clientA = makeClient();
    await clientA.waitConnected();
    const msg = await waitFor(clientA, (m) => m.type === 'SYSTEM', 2000, 'connected-as message');
    assert.strictEqual(msg.text, 'Connected as Client A');
  });

  let clientB;
  await test('Test 3: Client B connects and is assigned identity', async () => {
    clientB = makeClient();
    await clientB.waitConnected();
    const msg = await waitFor(clientB, (m) => m.type === 'SYSTEM', 2000, 'connected-as message');
    assert.strictEqual(msg.text, 'Connected as Client B');
  });

  await test('Test 4: Client A sends a message, Client B receives it', async () => {
    clientA.sendChat('whatever', 'Hello Bob');
    const msg = await waitFor(clientB, (m) => m.type === 'CHAT', 2000, 'chat from A');
    assert.strictEqual(msg.sender, 'Client A', 'server must stamp sender itself');
    assert.strictEqual(msg.text, 'Hello Bob');
  });

  await test('Test 5: Client B replies, Client A receives it', async () => {
    clientB.sendChat('whatever', 'Hi Alice');
    const msg = await waitFor(clientA, (m) => m.type === 'CHAT', 2000, 'chat from B');
    assert.strictEqual(msg.sender, 'Client B');
    assert.strictEqual(msg.text, 'Hi Alice');
  });

  await test('Test 6: several rapid messages arrive in order', async () => {
    const texts = ['one', 'two', 'three', 'four', 'five'];
    const startIndex = clientB.received.filter((m) => m.type === 'CHAT').length;
    for (const t of texts) {
      clientA.sendChat('whatever', t);
    }
    const deadline = Date.now() + 2000;
    while (clientB.received.filter((m) => m.type === 'CHAT').length < startIndex + texts.length && Date.now() < deadline) {
      await delay(20);
    }
    const chats = clientB.received.filter((m) => m.type === 'CHAT').slice(startIndex);
    assert.deepStrictEqual(chats.map((m) => m.text), texts);
  });

  await test('Test 7: message framing (split chunk + multiple per chunk)', async () => {
    const startIndex = clientB.received.filter((m) => m.type === 'CHAT').length;

    // One message split across two TCP writes.
    const fullLine = encode(createChatMessage('whatever', 'split-message'));
    const mid = Math.floor(fullLine.length / 2);
    clientA.rawWrite(fullLine.slice(0, mid));
    await delay(20);
    clientA.rawWrite(fullLine.slice(mid));

    // Two complete messages delivered in a single write.
    const combined = encode(createChatMessage('whatever', 'combo-1')) + encode(createChatMessage('whatever', 'combo-2'));
    await delay(20);
    clientA.rawWrite(combined);

    const deadline = Date.now() + 2000;
    while (clientB.received.filter((m) => m.type === 'CHAT').length < startIndex + 3 && Date.now() < deadline) {
      await delay(20);
    }
    const chats = clientB.received.filter((m) => m.type === 'CHAT').slice(startIndex);
    assert.deepStrictEqual(chats.map((m) => m.text), ['split-message', 'combo-1', 'combo-2']);
  });

  await test('Test 7b: malformed JSON does not crash the server', async () => {
    clientA.rawWrite('{not valid json\n');
    const msg = await waitFor(clientA, (m) => m.type === 'ERROR', 2000, 'malformed-JSON error reply');
    assert.ok(/invalid json/i.test(msg.text));

    // Server should still be alive and able to relay a subsequent valid message.
    clientA.sendChat('whatever', 'still-alive');
    const chat = await waitFor(clientB, (m) => m.type === 'CHAT' && m.text === 'still-alive', 2000, 'post-malformed chat');
    assert.strictEqual(chat.sender, 'Client A');
  });

  await test('Test 7c: empty message is ignored (no crash, nothing forwarded)', async () => {
    const startIndex = clientB.received.length;
    clientA.rawWrite('\n');
    clientA.sendChat('whatever', 'after-empty');
    const chat = await waitFor(clientB, (m) => m.type === 'CHAT' && m.text === 'after-empty', 2000, 'chat after empty line');
    assert.strictEqual(chat.sender, 'Client A');
    // No spurious message should have been produced for the blank line itself.
    const between = clientB.received.slice(startIndex, clientB.received.indexOf(chat));
    assert.strictEqual(between.length, 0);
  });

  await test('Test 8: disconnecting one client keeps the server stable and frees the slot', async () => {
    clientA.socket.end();
    await waitFor(clientB, (m) => m.type === 'SYSTEM' && /Client A has disconnected/.test(m.text), 2000, 'A disconnect notice');

    // A new client should now be able to take over the "Client A" slot.
    const clientA2 = makeClient();
    await clientA2.waitConnected();
    const msg = await waitFor(clientA2, (m) => m.type === 'SYSTEM', 2000, 'reconnect identity');
    assert.strictEqual(msg.text, 'Connected as Client A');
    clientA = clientA2;
  });

  await test('Test 9: a third client is rejected gracefully', async () => {
    const clientC = makeClient();
    await clientC.waitConnected();
    const msg = await waitFor(clientC, (m) => m.type === 'ERROR', 2000, 'server-full error');
    assert.ok(/already has two clients/i.test(msg.text));
    await new Promise((resolve) => clientC.socket.once('close', resolve));

    // Existing clients must be unaffected.
    clientA.sendChat('whatever', 'still-here');
    const chat = await waitFor(clientB, (m) => m.type === 'CHAT' && m.text === 'still-here', 2000, 'chat after rejection');
    assert.strictEqual(chat.sender, 'Client A');
  });

  await test('Test 10: server rejects structurally invalid protocol messages without crashing', async () => {
    const invalidPayloads = [
      {},
      { type: 'UNKNOWN' },
      { type: 'CHAT' },
      { type: 'CHAT', text: '' },
      { type: 'CHAT', text: 123 },
      { type: 'CHAT', version: 999, text: 'Hello' },
    ];

    for (const payload of invalidPayloads) {
      clientA.rawWrite(JSON.stringify(payload) + '\n');
      const msg = await waitFor(clientA, (m) => m.type === 'ERROR', 2000, `rejection of ${JSON.stringify(payload)}`);
      assert.strictEqual(msg.type, 'ERROR');
    }

    // Server must still be alive and relaying normally afterwards.
    clientA.sendChat('whatever', 'still-standing');
    const chat = await waitFor(clientB, (m) => m.type === 'CHAT' && m.text === 'still-standing', 2000, 'chat after invalid batch');
    assert.strictEqual(chat.sender, 'Client A');
  });

  await test('Test 11: a structurally valid but unaccepted type (SYSTEM) is rejected cleanly', async () => {
    // Phase 4: HELLO is now an accepted client message, so a client-sent SYSTEM stands in
    // for "valid type the server does not accept from clients".
    clientA.rawWrite(JSON.stringify({ type: 'SYSTEM', version: 1, text: 'forged notice' }) + '\n');
    const msg = await waitFor(clientA, (m) => m.type === 'ERROR', 2000, 'SYSTEM rejection');
    assert.ok(/does not accept "SYSTEM"/.test(msg.text));

    clientA.sendChat('whatever', 'after-system');
    const chat = await waitFor(clientB, (m) => m.type === 'CHAT' && m.text === 'after-system', 2000, 'chat after SYSTEM rejection');
    assert.strictEqual(chat.sender, 'Client A');
  });

  await test('Test 12: reserved future message types are rejected, not crashed on', async () => {
    clientA.rawWrite(JSON.stringify({ type: 'REKEY', version: 1 }) + '\n');
    const msg = await waitFor(clientA, (m) => m.type === 'ERROR', 2000, 'REKEY rejection');
    assert.ok(/reserved/i.test(msg.text));

    clientA.sendChat('whatever', 'after-reserved-type');
    const chat = await waitFor(clientB, (m) => m.type === 'CHAT' && m.text === 'after-reserved-type', 2000, 'chat after reserved-type rejection');
    assert.strictEqual(chat.sender, 'Client A');
  });

  clientA.socket.destroy();
  clientB.socket.destroy();
  serverProcess.kill();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('Test runner crashed:', err);
  process.exit(1);
});
