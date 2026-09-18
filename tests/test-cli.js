'use strict';

/**
 * CLI tests: real src/server.js and real src/client.js processes driven
 * through stdin/stdout, the way a person uses them in three terminals.
 * Run with: npm test
 */

const path = require('path');
const assert = require('assert');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SERVER_PATH = path.join(ROOT, 'src', 'server.js');
const CLIENT_PATH = path.join(ROOT, 'src', 'client.js');
const PORT = 5499;
const UNUSED_PORT = 5498;

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

function spawnProc(script, port) {
  const proc = spawn(process.execPath, [script, String(port)], { stdio: ['pipe', 'pipe', 'pipe'] });
  const handle = { proc, out: '', exitCode: null };
  proc.stdout.on('data', (d) => { handle.out += d.toString(); });
  proc.stderr.on('data', (d) => { handle.out += d.toString(); });
  proc.on('exit', (code) => { handle.exitCode = code; });
  handle.type = (line) => proc.stdin.write(line + '\n');
  return handle;
}

/** Text of `out` after the first occurrence of `marker` (so repeated commands can be told apart). */
function after(out, marker) {
  const i = out.lastIndexOf(marker);
  return i === -1 ? '' : out.slice(i);
}

const field = (out, label) => (out.match(new RegExp(`${label}: (\\S+)`)) || [])[1];

async function main() {
  console.log('Running CLI tests (real server + real clients)...');
  const server = spawnProc(SERVER_PATH, PORT);
  const running = [server];
  const startClient = () => {
    const c = spawnProc(CLIENT_PATH, PORT);
    running.push(c);
    return c;
  };

  await until(() => server.out.includes('Waiting for clients'), 5000, 'server to start');

  await test('CLI 1: the server prints its startup banner', async () => {
    assert.ok(/CipherLink Server\r?\nListening on 127\.0\.0\.1:5499\r?\nWaiting for clients\.\.\./.test(server.out), server.out);
  });

  const a = startClient();
  await test('CLI 2: Client A gets an identity, generates keys, and waits for the peer; /status shows NO_SESSION', async () => {
    await until(() => a.out.includes('Identity keys ready'), 30000, 'A to finish key generation');
    assert.ok(/Connected to CipherLink server\r?\nIdentity: Client A\r?\nGenerating identity keys\.\.\.\r?\nIdentity keys ready/.test(a.out), a.out);
    assert.ok(a.out.includes('Waiting for peer'));
    assert.ok(!a.out.includes('HELLO sent'), 'no HELLO is sent while nobody is there to receive it');
    a.type('/status');
    await until(() => a.out.includes('CipherLink Session Status'), 3000, '/status output');
    const status = after(a.out, 'CipherLink Session Status');
    assert.ok(/Identity: Client A/.test(status));
    assert.ok(/Peer: Client B \(not connected\)/.test(status));
    assert.ok(/State: NO_SESSION/.test(status));
  });

  const b = startClient();
  await test('CLI 3: Client B joins; the handshake progress is visible on both sides and both establish a session', async () => {
    await until(() => a.out.includes('[SESSION] Established') && b.out.includes('[SESSION] Established'), 30000, 'both sessions to be established');
    for (const line of ['[HANDSHAKE] HELLO sent', '[HANDSHAKE] HELLO received from Client B', '[HANDSHAKE] Peer public keys accepted',
      '[HANDSHAKE] Generating session key', '[HANDSHAKE] KEY_EXCHANGE sent', '[HANDSHAKE] KEY_EXCHANGE_ACK received from Client B']) {
      assert.ok(a.out.includes(line), `Client A output should contain "${line}"`);
    }
    for (const line of ['Identity: Client B', '[HANDSHAKE] HELLO sent', '[HANDSHAKE] HELLO received from Client A', '[HANDSHAKE] KEY_EXCHANGE received from Client A',
      '[HANDSHAKE] Signature verified', '[HANDSHAKE] Session key decrypted', '[HANDSHAKE] KEY_EXCHANGE_ACK sent']) {
      assert.ok(b.out.includes(line), `Client B output should contain "${line}"`);
    }
  });

  let firstId;
  let firstFingerprint;
  await test('CLI 4: /status on both clients shows ESTABLISHED with the same session ID and fingerprint, and no secrets', async () => {
    a.type('/status');
    b.type('/status');
    await until(() => after(a.out, 'CipherLink Session Status').includes('State: ESTABLISHED') && after(b.out, 'CipherLink Session Status').includes('State: ESTABLISHED'), 3000, '/status on both');
    const statusA = after(a.out, 'CipherLink Session Status');
    const statusB = after(b.out, 'CipherLink Session Status');
    assert.ok(/Peer: Client B \(connected\)/.test(statusA));
    firstId = field(statusA, 'Session ID');
    firstFingerprint = field(statusA, 'Session key fingerprint');
    assert.ok(/^[0-9a-f]{32}$/.test(firstId));
    assert.ok(/^[0-9a-f]{8}\.\.\.[0-9a-f]{8}$/.test(firstFingerprint));
    assert.strictEqual(field(statusB, 'Session ID'), firstId, 'same session ID on both clients');
    assert.strictEqual(field(statusB, 'Session key fingerprint'), firstFingerprint, 'same fingerprint on both clients');
    for (const out of [a.out, b.out, server.out]) {
      assert.ok(!/[0-9a-f]{64}/.test(out), 'no raw 256-bit value may appear in any output');
      assert.ok(!/BEGIN [A-Z ]*KEY|PRIVATE/.test(out), 'no PEM/private key material may appear in any output');
    }
  });

  await test('CLI 5: plaintext chat works in both directions', async () => {
    a.type('Hello Bob');
    await until(() => b.out.includes('Client A: Hello Bob'), 3000, 'B to receive Hello Bob');
    b.type('Hi Alice');
    await until(() => a.out.includes('Client B: Hi Alice'), 3000, 'A to receive Hi Alice');
  });

  await test('CLI 6: /help works, and an unknown /command is not sent to the peer as chat', async () => {
    a.type('/help');
    await until(() => a.out.includes('/quit'), 3000, '/help output');
    a.type('/bogus');
    await until(() => a.out.includes('Unknown command "/bogus"'), 3000, 'unknown-command notice');
    a.type('marker-after-bogus');
    await until(() => b.out.includes('Client A: marker-after-bogus'), 3000, 'B to receive the marker');
    assert.ok(!b.out.includes('/bogus'), 'the mistyped command must not reach the peer');
  });

  await test('CLI 7: a message over the frame limit is refused locally and the connection survives', async () => {
    a.type('x'.repeat(70000));
    await until(() => a.out.includes('Message too long'), 3000, 'local length refusal');
    a.type('still-connected');
    await until(() => b.out.includes('Client A: still-connected'), 3000, 'chat after the refusal');
    assert.ok(!b.out.includes('xxxxxxxxxx'));
  });

  await test('CLI 8: a third client is rejected; A and B keep working', async () => {
    const c = startClient();
    await until(() => c.exitCode !== null, 30000, 'C to exit');
    assert.ok(/already has two clients/.test(c.out), c.out);
    a.type('after-third');
    await until(() => b.out.includes('Client A: after-third'), 3000, 'chat after the third client was rejected');
  });

  await test('CLI 9: /quit exits cleanly; the peer is told and clears its session', async () => {
    a.type('/quit');
    await until(() => a.exitCode !== null, 5000, 'A to exit');
    assert.strictEqual(a.exitCode, 0);
    await until(() => b.out.includes('[SESSION] Ended'), 3000, 'B to report the session ended');
    assert.ok(b.out.includes('Client A has disconnected'));
    b.type('/status');
    await until(() => /Peer: Client A \(not connected\)/.test(after(b.out, 'CipherLink Session Status')), 3000, 'B /status after peer left');
    assert.ok(/State: NO_SESSION/.test(after(b.out, 'CipherLink Session Status')));
  });

  await test('CLI 10: a reconnecting Client A generates new keys and gets a NEW session ID and fingerprint', async () => {
    const a2 = startClient();
    await until(() => a2.out.includes('[SESSION] Established') && b.out.split('[SESSION] Established with').length > 2, 30000, 'the new session');
    assert.ok(a2.out.includes('Identity: Client A'));
    a2.type('/status');
    b.type('/status');
    await until(() => after(a2.out, 'CipherLink Session Status').includes('State: ESTABLISHED') && after(b.out, 'CipherLink Session Status').includes('State: ESTABLISHED'), 3000, '/status after reconnect');
    const newId = field(after(a2.out, 'CipherLink Session Status'), 'Session ID');
    const newFingerprint = field(after(a2.out, 'CipherLink Session Status'), 'Session key fingerprint');
    assert.notStrictEqual(newId, firstId, 'new session ID');
    assert.notStrictEqual(newFingerprint, firstFingerprint, 'new session key (different fingerprint)');
    assert.strictEqual(field(after(b.out, 'CipherLink Session Status'), 'Session ID'), newId);
    assert.strictEqual(field(after(b.out, 'CipherLink Session Status'), 'Session key fingerprint'), newFingerprint);
    a2.type('hello-again');
    await until(() => b.out.includes('Client A: hello-again'), 3000, 'chat after reconnect');
  });

  await test('CLI 11: the server log shows handshake message types and connections, but no keys or handshake contents', async () => {
    for (const type of ['HELLO', 'KEY_EXCHANGE', 'KEY_EXCHANGE_ACK']) {
      assert.ok(server.out.includes(`-> Client`) && new RegExp(`Client [AB] -> Client [AB]: ${type}`).test(server.out), `server should log ${type}`);
    }
    assert.ok(!/[A-Za-z0-9+/=]{40,}/.test(server.out), 'no long base64/hex blobs (keys, ciphertext, signatures) in the server log');
    assert.ok(!/BEGIN|PRIVATE|sessionKey|encryptedSessionKey|signature/i.test(server.out));
  });

  await test('CLI 12: with no server running the client explains what to do and exits with an error', async () => {
    const lonely = spawnProc(CLIENT_PATH, UNUSED_PORT);
    await until(() => lonely.exitCode !== null, 15000, 'client to give up');
    assert.strictEqual(lonely.exitCode, 1);
    assert.ok(/Is the server running\? Start it with: npm run server/.test(lonely.out), lonely.out);
  });

  for (const handle of running) handle.proc.kill();
  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('CLI test runner crashed:', err);
  process.exit(1);
});
