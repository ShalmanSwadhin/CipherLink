'use strict';

/**
 * Frame-size limit tests.
 *   Part 1: LineBuffer unit tests (no sockets).
 *   Part 2: the real server under oversized frames - it must reply with an
 *           error, close only the offending connection, keep its memory
 *           bounded, and keep serving the other client.
 * Run with: npm test
 */

const net = require('net');
const path = require('path');
const assert = require('assert');
const { spawn, execFileSync } = require('child_process');
const {
  MAX_FRAME_SIZE,
  FrameTooLargeError,
  LineBuffer,
  encode,
  decode,
  createChatMessage,
  createHelloMessage,
} = require('../src/protocol/message');
const { createIdentity, exportPublicKeys } = require('../src/security/identity');

const SERVER_PATH = path.join(__dirname, '..', 'src', 'server.js');
const PORT = 5399;

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

// ---- Part 1: LineBuffer ------------------------------------------------------

function unitTests() {
  console.log('Frame-limit unit tests (LineBuffer)...');
  const sync = (name, fn) => {
    try {
      fn();
      passed++;
      console.log(`  PASS - ${name}`);
    } catch (err) {
      failed++;
      console.log(`  FAIL - ${name}`);
      console.log(`         ${err.message}`);
    }
  };

  sync('Frame 1: the default limit is 64 KiB and far above a real handshake message', () => {
    assert.strictEqual(MAX_FRAME_SIZE, 64 * 1024);
    const pems = exportPublicKeys(createIdentity());
    const hello = encode(createHelloMessage('Client A', pems.encryptionPublicKey, pems.signingPublicKey));
    assert.ok(hello.length > 1000 && hello.length < 2500, `HELLO is ${hello.length} bytes`);
    assert.ok(hello.length * 20 < MAX_FRAME_SIZE, 'limit leaves large headroom');
    const buf = new LineBuffer();
    assert.deepStrictEqual(buf.append(hello), [hello.slice(0, -1)]);
  });

  sync('Frame 2: a frame of exactly the limit is accepted; one byte more is rejected', () => {
    assert.deepStrictEqual(new LineBuffer(100).append('a'.repeat(100) + '\n'), ['a'.repeat(100)]);
    assert.throws(() => new LineBuffer(100).append('a'.repeat(101) + '\n'), FrameTooLargeError);
  });

  sync('Frame 3: a never-ending frame (no newline) is rejected and the buffer is emptied', () => {
    const buf = new LineBuffer(100);
    assert.deepStrictEqual(buf.append('a'.repeat(40)), []);
    assert.deepStrictEqual(buf.append('a'.repeat(40)), []);
    assert.ok(buf._buffer.length <= 100, 'buffer never holds more than one frame');
    assert.throws(() => buf.append('a'.repeat(40)), (err) => err instanceof FrameTooLargeError && err.maxFrameSize === 100);
    assert.strictEqual(buf._buffer, '', 'nothing is retained after the error');
  });

  sync('Frame 4: an oversized frame in the same chunk as valid ones is rejected', () => {
    assert.throws(() => new LineBuffer(100).append('ok\n' + 'b'.repeat(200) + '\nok2\n'), FrameTooLargeError);
  });

  sync('Frame 5: the limit counts UTF-8 bytes, not characters', () => {
    const euros = '€'.repeat(40); // 40 characters, 120 bytes
    assert.strictEqual(euros.length, 40);
    assert.throws(() => new LineBuffer(100).append(euros + '\n'), FrameTooLargeError);
    assert.deepStrictEqual(new LineBuffer(120).append(euros + '\n'), [euros]);
  });

  sync('Frame 6: ordinary framing still works (split lines, multiple lines per chunk)', () => {
    const buf = new LineBuffer(100);
    assert.deepStrictEqual(buf.append('{"a":'), []);
    assert.deepStrictEqual(buf.append('1}\n{"b":2}\n{"c"'), ['{"a":1}', '{"b":2}']);
    assert.deepStrictEqual(buf.append(':3}\n'), ['{"c":3}']);
  });
}

// ---- Part 2: the real server ---------------------------------------------------

class Raw {
  constructor(port) {
    this.messages = [];
    this.selfId = null;
    this.closed = false;
    this.buffer = new LineBuffer();
    this.socket = net.createConnection({ host: '127.0.0.1', port });
    this.socket.on('data', (chunk) => {
      for (const line of this.buffer.append(chunk.toString('utf8'))) {
        if (line.trim() === '') continue;
        const msg = decode(line);
        this.messages.push(msg);
        if (msg.type === 'SYSTEM' && msg.text.startsWith('Connected as ')) {
          this.selfId = msg.text.slice('Connected as '.length);
        }
      }
    });
    this.socket.on('close', () => { this.closed = true; });
    this.socket.on('error', () => {});
  }

  sendChat(text) {
    this.socket.write(encode(createChatMessage(this.selfId, text)));
  }

  hasChat(text) {
    return this.messages.some((m) => m.type === 'CHAT' && m.text === text);
  }

  hasEvent(event) {
    return this.messages.some((m) => m.event === event);
  }

  hasError(pattern) {
    return this.messages.some((m) => m.type === 'ERROR' && pattern.test(m.text));
  }
}

/** Streams `totalBytes` of newline-free data, respecting backpressure; stops once the server closes us. */
async function streamWithoutNewline(raw, totalBytes) {
  const chunk = Buffer.alloc(64 * 1024, 0x78);
  let sent = 0;
  while (sent < totalBytes && !raw.closed && !raw.socket.destroyed) {
    if (!raw.socket.write(chunk)) {
      await new Promise((resolve) => {
        const done = () => {
          raw.socket.off('drain', done);
          raw.socket.off('close', done);
          resolve();
        };
        raw.socket.on('drain', done);
        raw.socket.on('close', done);
      });
    }
    sent += chunk.length;
  }
  return sent;
}

function rssMB(pid) {
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH']).toString();
      return Number(out.trim().split('","').pop().replace(/[^0-9]/g, '')) / 1024;
    }
    return Number(execFileSync('ps', ['-o', 'rss=', '-p', String(pid)]).toString().trim()) / 1024;
  } catch (err) {
    return null;
  }
}

async function integrationTests() {
  console.log('Frame-limit integration tests (real server)...');
  const server = spawn(process.execPath, [SERVER_PATH, String(PORT)], { stdio: 'pipe' });
  let output = '';
  server.stdout.on('data', (d) => { output += d.toString(); });
  server.stderr.on('data', (d) => { output += d.toString(); });
  const sockets = [];
  const connect = async () => {
    const raw = new Raw(PORT);
    sockets.push(raw);
    await until(() => raw.selfId !== null || raw.closed, 3000, 'identity assignment');
    return raw;
  };

  await until(() => output.includes('Waiting for clients'), 5000, 'server to start');

  let a = await connect();
  const b = await connect();
  assert.deepStrictEqual([a.selfId, b.selfId], ['Client A', 'Client B']);

  await test('Frame 7: a 200 KB frame gets an ERROR and a closed connection; the other client and the server survive', async () => {
    a.socket.write('x'.repeat(200 * 1024) + '\n');
    await until(() => a.hasError(/maximum size/), 3000, 'frame-size ERROR');
    await until(() => a.closed, 3000, 'server to close the offending connection');
    await until(() => b.hasEvent('PEER_LEFT'), 3000, 'B to be told A left');
    assert.ok(!b.closed, 'the well-behaved client stays connected');
    assert.ok(/larger than 65536 bytes/.test(output), 'the event is logged');

    a = await connect(); // the slot is free again and the server still accepts clients
    assert.strictEqual(a.selfId, 'Client A');
    a.sendChat('after-oversize');
    await until(() => b.hasChat('after-oversize'), 3000, 'normal chat after the oversize incident');
  });

  await test('Frame 8: a never-ending frame is cut off early and server memory stays bounded', async () => {
    const before = rssMB(server.pid);
    const sent = await streamWithoutNewline(a, 200 * 1024 * 1024); // 200 MB, never a newline
    await until(() => a.closed, 5000, 'server to drop the flooding connection');
    assert.ok(a.hasError(/maximum size/), 'the sender is told why');
    await delay(500);
    const after = rssMB(server.pid);
    console.log(`         (streamed ${(sent / 1048576).toFixed(0)} MB; server RSS ${before === null ? 'n/a' : before.toFixed(0)} MB -> ${after === null ? 'n/a' : after.toFixed(0)} MB)`);
    if (before !== null && after !== null) {
      assert.ok(after - before < 80, `server memory grew by ${(after - before).toFixed(0)} MB`);
    }
    await until(() => b.hasEvent('PEER_LEFT'), 3000, 'PEER_LEFT for the dropped client');
    assert.ok(!b.closed);

    a = await connect();
    a.sendChat('after-flood');
    await until(() => b.hasChat('after-flood'), 3000, 'normal chat after the flood');
  });

  await test('Frame 9: large-but-legal chat (30,000 chars) relays intact; an over-limit chat (70,000 chars) drops only the sender', async () => {
    const big = 'y'.repeat(30000);
    a.sendChat(big);
    await until(() => b.hasChat(big), 3000, '30,000-char chat');

    a.sendChat('z'.repeat(70000));
    await until(() => a.hasError(/maximum size/), 3000, 'over-limit ERROR');
    await until(() => a.closed, 3000, 'sender to be closed');
    assert.ok(!b.messages.some((m) => m.type === 'CHAT' && m.text.startsWith('zzz')), 'the over-limit message is never relayed');
    assert.ok(!b.closed);
  });

  await test('Frame 10: normal handshake-sized traffic is unaffected by the limit', async () => {
    a = await connect();
    const pems = exportPublicKeys(createIdentity());
    const hello = createHelloMessage('Client A', pems.encryptionPublicKey, pems.signingPublicKey);
    const before = b.messages.length;
    a.socket.write(encode(hello));
    await until(() => b.messages.slice(before).some((m) => m.type === 'HELLO'), 3000, 'HELLO relayed');
    assert.ok(!a.closed);
  });

  for (const raw of sockets) raw.socket.destroy();
  server.kill();
}

async function main() {
  unitTests();
  await integrationTests();
  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('Frame-limit test runner crashed:', err);
  process.exit(1);
});
