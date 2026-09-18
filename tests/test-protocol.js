'use strict';

/**
 * Unit tests for src/protocol/message.js - pure functions, no sockets.
 * Run with: npm test (also runs tests/test-server.js)
 */

const assert = require('assert');
const {
  PROTOCOL_VERSION,
  MESSAGE_TYPES,
  createHelloMessage,
  createChatMessage,
  createSystemMessage,
  createErrorMessage,
  validateMessage,
  LineBuffer,
} = require('../src/protocol/message');
const { generateKeyPair, exportPublicKey } = require('../src/crypto/keys');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS - ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL - ${name}`);
    console.log(`         ${err.message}`);
  }
}

function assertValid(msg, label) {
  const result = validateMessage(msg);
  assert.strictEqual(result.valid, true, `${label}: expected valid, got reason "${result.reason}"`);
}

function assertInvalid(msg, label) {
  const result = validateMessage(msg);
  assert.strictEqual(result.valid, false, `${label}: expected invalid, but it passed validation`);
  assert.strictEqual(typeof result.reason, 'string');
  assert.ok(result.reason.length > 0, `${label}: expected a non-empty reason string`);
}

console.log('Running protocol unit tests...');

// --- Valid messages -------------------------------------------------------

test('valid CHAT message (factory output)', () => {
  assertValid(createChatMessage('Client A', 'Hello Bob'), 'CHAT factory');
});

test('valid SYSTEM message (factory output)', () => {
  assertValid(createSystemMessage('Connected as Client A'), 'SYSTEM factory');
});

test('valid ERROR message (factory output)', () => {
  assertValid(createErrorMessage('Something went wrong'), 'ERROR factory');
});

test('valid HELLO message (factory output)', () => {
  // Phase 4: a HELLO carries the sender's two public keys (a key-less HELLO is now invalid).
  const encryptionPublicKey = exportPublicKey(generateKeyPair().publicKey);
  const signingPublicKey = exportPublicKey(generateKeyPair().publicKey);
  assertValid(createHelloMessage('Client A', encryptionPublicKey, signingPublicKey), 'HELLO factory');
});

test('factories stamp the current protocol version', () => {
  assert.strictEqual(createChatMessage('Client A', 'hi').version, PROTOCOL_VERSION);
  assert.strictEqual(createHelloMessage('Client A').version, PROTOCOL_VERSION);
});

test('CHAT without an explicit version is still valid (implicit v1)', () => {
  assertValid({ type: 'CHAT', sender: 'Client A', text: 'hi' }, 'versionless CHAT');
});

// --- Invalid messages (from the Phase 2 spec) ------------------------------

test('reject {} (no type at all)', () => {
  assertInvalid({}, 'empty object');
});

test('reject unknown message type', () => {
  assertInvalid({ type: 'UNKNOWN' }, 'unknown type');
});

test('reject CHAT with missing text', () => {
  assertInvalid({ type: 'CHAT' }, 'CHAT missing text');
});

test('reject CHAT with empty text', () => {
  assertInvalid({ type: 'CHAT', text: '' }, 'CHAT empty text');
});

test('reject CHAT with non-string text', () => {
  assertInvalid({ type: 'CHAT', text: 123 }, 'CHAT numeric text');
});

test('reject CHAT with unsupported version', () => {
  assertInvalid({ type: 'CHAT', version: 999, text: 'Hello' }, 'CHAT bad version');
});

// --- Additional structural edge cases --------------------------------------

test('reject null', () => {
  assertInvalid(null, 'null');
});

test('reject an array', () => {
  assertInvalid([1, 2, 3], 'array');
});

test('reject a bare string', () => {
  assertInvalid('CHAT', 'bare string');
});

test('reject HELLO with missing sender', () => {
  assertInvalid({ type: 'HELLO', version: 1 }, 'HELLO missing sender');
});

test('reject SYSTEM/ERROR with empty text', () => {
  assertInvalid({ type: 'SYSTEM', text: '' }, 'SYSTEM empty text');
  assertInvalid({ type: 'ERROR', text: '   ' }, 'ERROR whitespace-only text');
});

test('reserved future types are recognized but rejected as not-yet-supported', () => {
  // Phase 4 implemented KEY_EXCHANGE / KEY_EXCHANGE_ACK; only rekeying is still reserved.
  for (const type of ['REKEY', 'REKEY_ACK']) {
    const result = validateMessage({ type, version: 1 });
    assert.strictEqual(result.valid, false, `${type} should not validate yet`);
    assert.ok(/reserved/i.test(result.reason), `${type} rejection reason should mention it is reserved`);
  }
  for (const type of ['KEY_EXCHANGE', 'KEY_EXCHANGE_ACK']) {
    const result = validateMessage({ type, version: 1 });
    assert.strictEqual(result.valid, false, `${type} without its fields is invalid`);
    assert.ok(!/reserved/i.test(result.reason), `${type} is implemented, no longer reserved`);
  }
});

// --- Framing layer is untouched by protocol changes ------------------------

test('LineBuffer still splits multiple lines and buffers partial ones', () => {
  const buf = new LineBuffer();
  let lines = buf.append('{"a":1}\n{"a":2}\npartial');
  assert.deepStrictEqual(lines, ['{"a":1}', '{"a":2}']);
  lines = buf.append('-rest\n');
  assert.deepStrictEqual(lines, ['partial-rest']);
});

console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
