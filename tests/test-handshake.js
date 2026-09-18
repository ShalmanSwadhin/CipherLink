'use strict';

/**
 * Phase 4 unit tests: HELLO validation, session-key establishment,
 * handshake tamper resistance, canonicalization and the session state
 * machine. No sockets: an in-memory "relay" carries messages between two
 * PeerSessions and records exactly what a server would see.
 * Run with: npm test
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const {
  MESSAGE_TYPES,
  PEER_EVENTS,
  encode,
  createHelloMessage,
  createSystemMessage,
  createPeerEventMessage,
  validateMessage,
} = require('../src/protocol/message');
const { canonicalizeHandshake } = require('../src/protocol/canonical');
const { generateKeyPair, exportPublicKey, exportPrivateKey } = require('../src/crypto/keys');
const { sign, verify } = require('../src/crypto/signing');
const { rsaDecrypt } = require('../src/crypto/rsa');
const { publicKeyFingerprint, sessionKeyFingerprint } = require('../src/crypto/hash');
const { createIdentity, exportPublicKeys } = require('../src/security/identity');
const {
  HandshakeError,
  createKeyExchange,
  verifyKeyExchange,
  createKeyExchangeAck,
  verifyKeyExchangeAck,
} = require('../src/security/handshake');
const { PeerSession, SESSION_STATES } = require('../src/security/peer-session');

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
  assert.strictEqual(result.valid, true, `${label}: expected valid, got "${result.reason}"`);
}

function assertInvalid(msg, label, reasonPattern) {
  const result = validateMessage(msg);
  assert.strictEqual(result.valid, false, `${label}: expected invalid but it validated`);
  if (reasonPattern) {
    assert.ok(reasonPattern.test(result.reason), `${label}: reason "${result.reason}" should match ${reasonPattern}`);
  }
}

function assertHandshakeError(fn, pattern, label) {
  assert.throws(fn, (err) => err instanceof HandshakeError && (!pattern || pattern.test(err.message)), label);
}

function flipBase64Byte(b64, index) {
  const bytes = Buffer.from(b64, 'base64');
  bytes[index] ^= 0x01;
  return bytes.toString('base64');
}

console.log('Running Phase 4 handshake unit tests...');

const idA = createIdentity();
const idB = createIdentity();
const idC = createIdentity(); // third party / attacker
const pemsA = exportPublicKeys(idA);
const pemsB = exportPublicKeys(idB);

function helloOf(pems, sender) {
  return createHelloMessage(sender, pems.encryptionPublicKey, pems.signingPublicKey);
}

/** Runs the complete handshake between two sessions; returns everything a relay would see. */
function runHandshake(identityA, identityB) {
  const a = new PeerSession({ selfId: 'Client A', identity: identityA });
  const b = new PeerSession({ selfId: 'Client B', identity: identityB });
  const wire = []; // every message any client put on the wire (what the server receives)

  const helloA = a.onPeerJoined().outgoing;
  const helloB = b.onPeerJoined().outgoing;
  wire.push(...helloA, ...helloB);

  assert.strictEqual(b.handleMessage(helloA[0]).error, null);
  const aResult = a.handleMessage(helloB[0]);
  assert.strictEqual(aResult.error, null);
  const keyExchange = aResult.outgoing.find((m) => m.type === MESSAGE_TYPES.KEY_EXCHANGE);
  assert.ok(keyExchange, 'A must send KEY_EXCHANGE after receiving B\'s HELLO');
  wire.push(...aResult.outgoing);

  const bResult = b.handleMessage(keyExchange);
  assert.strictEqual(bResult.error, null);
  wire.push(...bResult.outgoing);
  const ack = bResult.outgoing[0];

  const finalResult = a.handleMessage(ack);
  assert.strictEqual(finalResult.error, null);
  return { a, b, wire, keyExchange, ack };
}

/** A fresh, valid KEY_EXCHANGE from A to B plus the material needed to verify it. */
function freshKeyExchange() {
  const exchange = createKeyExchange({
    sender: 'Client A',
    recipient: 'Client B',
    signingPrivateKey: idA.signing.privateKey,
    peerEncryptionPublicKey: idB.encryption.publicKey,
  });
  const verifyArgs = (message, overrides = {}) => ({
    message,
    expectedSender: 'Client A',
    expectedRecipient: 'Client B',
    peerSigningPublicKey: idA.signing.publicKey,
    ownEncryptionPublicKey: idB.encryption.publicKey,
    ownEncryptionPrivateKey: idB.encryption.privateKey,
    ...overrides,
  });
  return { ...exchange, verifyArgs };
}

// === HELLO tests (spec 1-8) ===================================================

test('HELLO 1: a valid HELLO with both public keys is accepted', () => {
  assertValid(helloOf(pemsA, 'Client A'), 'HELLO');
  assert.deepStrictEqual(Object.keys(helloOf(pemsA, 'Client A')), ['type', 'version', 'sender', 'encryptionPublicKey', 'signingPublicKey']);
});

test('HELLO 2: missing encryptionPublicKey is rejected', () => {
  const hello = helloOf(pemsA, 'Client A');
  delete hello.encryptionPublicKey;
  assertInvalid(hello, 'no encryption key', /encryptionPublicKey/);
});

test('HELLO 3: missing signingPublicKey is rejected', () => {
  const hello = helloOf(pemsA, 'Client A');
  delete hello.signingPublicKey;
  assertInvalid(hello, 'no signing key', /signingPublicKey/);
});

test('HELLO 4: an invalid encryption key is rejected (garbage, wrong type, weak, non-RSA)', () => {
  const weak = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' });
  for (const bad of ['not a key', '', 123, null, weak, ec, '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n']) {
    assertInvalid({ ...helloOf(pemsA, 'Client A'), encryptionPublicKey: bad }, `bad encryption key ${String(bad).slice(0, 20)}`, /encryptionPublicKey/);
  }
});

test('HELLO 5: an invalid signing key is rejected', () => {
  const weak = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
  for (const bad of ['not a key', '', 123, null, weak]) {
    assertInvalid({ ...helloOf(pemsA, 'Client A'), signingPublicKey: bad }, `bad signing key ${String(bad).slice(0, 20)}`, /signingPublicKey/);
  }
});

test('HELLO 6: private key material is rejected', () => {
  const privatePem = exportPrivateKey(idA.encryption.privateKey);
  // A private key in a key field:
  assertInvalid({ ...helloOf(pemsA, 'Client A'), encryptionPublicKey: privatePem }, 'private key as encryption key', /private key/i);
  assertInvalid({ ...helloOf(pemsA, 'Client A'), signingPublicKey: exportPrivateKey(idA.signing.privateKey) }, 'private key as signing key', /private key/i);
  // A private key smuggled in an extra field (any name mentioning "private", or any value carrying one):
  assertInvalid({ ...helloOf(pemsA, 'Client A'), encryptionPrivateKey: privatePem }, 'extra privateKey field', /private key/i);
  assertInvalid({ ...helloOf(pemsA, 'Client A'), note: privatePem }, 'private PEM in unrelated field', /private key/i);
  // Handshake messages other than HELLO too:
  const { message } = freshKeyExchange();
  assertInvalid({ ...message, signingPrivateKey: privatePem }, 'private key in KEY_EXCHANGE', /private key/i);
});

test('HELLO 7: an unsupported or missing protocol version is rejected', () => {
  for (const version of [999, 0, 2, '1', null]) {
    assertInvalid({ ...helloOf(pemsA, 'Client A'), version }, `version ${version}`, /version/i);
  }
  const noVersion = helloOf(pemsA, 'Client A');
  delete noVersion.version;
  assertInvalid(noVersion, 'missing version', /version/i);
});

test('HELLO 8: a sender that is not the expected peer is rejected', () => {
  const sessionB = new PeerSession({ selfId: 'Client B', identity: idB });
  for (const claimedSender of ['Client B', 'Client C', 'Mallory']) {
    const result = sessionB.handleMessage(helloOf(pemsA, claimedSender));
    assert.ok(result.error, `HELLO claiming ${claimedSender} must be rejected`);
    assert.strictEqual(sessionB.state, SESSION_STATES.NO_SESSION, 'a rejected HELLO must not change state');
    assert.strictEqual(sessionB.peerSigningPublicKey, null);
  }
  assert.strictEqual(sessionB.handleMessage(helloOf(pemsA, 'Client A')).error, null);
  assertInvalid({ ...helloOf(pemsA, 'Client A'), sender: '' }, 'empty sender', /sender/);
});

test('HELLO extra: identical encryption and signing keys, unknown fields and oversize PEMs are rejected', () => {
  assertInvalid(
    createHelloMessage('Client A', pemsA.encryptionPublicKey, pemsA.encryptionPublicKey),
    'same key for both purposes',
    /must not be reused/
  );
  assertInvalid({ ...helloOf(pemsA, 'Client A'), extra: 'x' }, 'unknown field', /unexpected field/);
  assertInvalid({ ...helloOf(pemsA, 'Client A'), encryptionPublicKey: pemsA.encryptionPublicKey + ' '.repeat(5000) }, 'oversize PEM', /encryptionPublicKey/);
});

// === Session-key establishment (spec 9-15) ====================================

test('Session 9: Client A generates a 32-byte session key', () => {
  const { sessionKey, sessionId } = freshKeyExchange();
  assert.ok(Buffer.isBuffer(sessionKey));
  assert.strictEqual(sessionKey.length, 32);
  assert.ok(/^[0-9a-f]{32}$/.test(sessionId), 'session ID is 128 random bits as hex');
});

test('Session 10: A wraps the key with RSA-OAEP for B\'s encryption key (only B can unwrap it)', () => {
  const { message, sessionKey } = freshKeyExchange();
  const ciphertext = Buffer.from(message.encryptedSessionKey, 'base64');
  assert.strictEqual(ciphertext.length, 384);
  assert.ok(!ciphertext.includes(sessionKey));
  assert.ok(rsaDecrypt(idB.encryption.privateKey, ciphertext).equals(sessionKey));
  assert.throws(() => rsaDecrypt(idC.encryption.privateKey, ciphertext), /decryption failed/);
  assert.throws(() => rsaDecrypt(idA.signing.privateKey, ciphertext), /decryption failed/, 'the signing key cannot unwrap it either');
});

test('Session 11: A signs the canonical handshake payload with its signing key', () => {
  const { message } = freshKeyExchange();
  assertValid(message, 'KEY_EXCHANGE');
  assert.deepStrictEqual(
    Object.keys(message),
    ['type', 'version', 'sender', 'recipient', 'sessionId', 'encryptedSessionKey', 'signature']
  );
  assert.strictEqual(Buffer.from(message.signature, 'base64').length, 384);
});

test('Session 12: B verifies A\'s signature over the exact signed context', () => {
  const { message } = freshKeyExchange();
  const signedData = canonicalizeHandshake({
    version: message.version,
    type: message.type,
    sender: message.sender,
    recipient: message.recipient,
    sessionId: message.sessionId,
    encryptedSessionKey: Buffer.from(message.encryptedSessionKey, 'base64'),
    recipientEncryptionKeyFingerprint: publicKeyFingerprint(idB.encryption.publicKey),
  });
  assert.strictEqual(verify(idA.signing.publicKey, signedData, Buffer.from(message.signature, 'base64')), true);
  assert.strictEqual(verify(idA.encryption.publicKey, signedData, Buffer.from(message.signature, 'base64')), false, 'not verifiable with A\'s encryption key');
});

test('Session 13: B decrypts the session key only after authenticating the message', () => {
  const { message, sessionKey, sessionId, verifyArgs } = freshKeyExchange();
  const result = verifyKeyExchange(verifyArgs(message));
  assert.ok(result.sessionKey.equals(sessionKey));
  assert.strictEqual(result.sessionId, sessionId);

  // Signature failure must win: a tampered message is rejected without any decryption result.
  const tampered = { ...message, encryptedSessionKey: flipBase64Byte(message.encryptedSessionKey, 5) };
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(tampered)), /Invalid signature/);
});

test('Session 14: A and B end the full handshake with identical session keys', () => {
  const { a, b } = runHandshake(idA, idB);
  assert.strictEqual(a.state, SESSION_STATES.ESTABLISHED);
  assert.strictEqual(b.state, SESSION_STATES.ESTABLISHED);
  assert.ok(a.sessionKey.equals(b.sessionKey));
  assert.strictEqual(a.sessionKey.length, 32);
  assert.strictEqual(a.sessionId, b.sessionId);
  assert.strictEqual(a.sessionKeyFingerprint(), b.sessionKeyFingerprint());
  // Each side learned the other's public keys from HELLO.
  assert.ok(a.peerSigningPublicKey.equals(idB.signing.publicKey));
  assert.ok(b.peerEncryptionPublicKey.equals(idA.encryption.publicKey));
});

test('Session 15: the server (everything on the wire) never receives the plaintext session key', () => {
  const { a, wire } = runHandshake(idA, idB);
  const key = a.sessionKey;
  const wireText = wire.map((m) => encode(m)).join('');
  const encodings = [key.toString('hex'), key.toString('base64'), key.toString('base64url'), key.toString('latin1')];
  for (const form of encodings) {
    assert.ok(!wireText.includes(form), 'session key must not appear on the wire in any encoding');
  }
  // Nor any private key.
  for (const identity of [idA, idB]) {
    for (const pair of [identity.encryption, identity.signing]) {
      for (const line of exportPrivateKey(pair.privateKey).trim().split('\n').slice(1, -1)) {
        assert.ok(!wireText.includes(line), 'private key material must not appear on the wire');
      }
    }
  }
  // Only the two public keys, ids, ciphertext and signatures are ever sent.
  assert.deepStrictEqual(wire.map((m) => m.type), ['HELLO', 'HELLO', 'KEY_EXCHANGE', 'KEY_EXCHANGE_ACK']);
});

// === Signature / handshake attack tests (spec 16-23) ==========================

test('Attack 16: a modified encrypted session key fails signature verification', () => {
  const { message, verifyArgs } = freshKeyExchange();
  for (const index of [0, 100, 383]) {
    const tampered = { ...message, encryptedSessionKey: flipBase64Byte(message.encryptedSessionKey, index) };
    assertHandshakeError(() => verifyKeyExchange(verifyArgs(tampered)), /Invalid signature/, `flip byte ${index}`);
  }
});

test('Attack 17: a modified sender fails verification (sender is signed)', () => {
  const { message, verifyArgs } = freshKeyExchange();
  const tampered = { ...message, sender: 'Client C' };
  // Expecting the forged sender to isolate the SIGNATURE binding from the sender check:
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(tampered, { expectedSender: 'Client C' })), /Invalid signature/);
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(tampered)), /Unexpected sender/);
});

test('Attack 18: a modified recipient fails verification (recipient is signed)', () => {
  const { message, verifyArgs } = freshKeyExchange();
  const tampered = { ...message, recipient: 'Client C' };
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(tampered, { expectedRecipient: 'Client C' })), /Invalid signature/);
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(tampered)), /not addressed/);
});

test('Attack 19: a modified session ID fails verification (session ID is signed)', () => {
  const { message, verifyArgs } = freshKeyExchange();
  const tampered = { ...message, sessionId: 'f'.repeat(32) };
  assert.notStrictEqual(tampered.sessionId, message.sessionId);
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(tampered)), /Invalid signature/);
});

test('Attack 20: a modified protocol version fails verification (version is signed)', () => {
  const { message, verifyArgs } = freshKeyExchange();
  // The receiver refuses an unsupported version outright...
  assertHandshakeError(() => verifyKeyExchange(verifyArgs({ ...message, version: 2 })), /Malformed/);
  // ...and, independently, the signature itself covers the version:
  const signedFor = (version) => canonicalizeHandshake({
    version,
    type: message.type,
    sender: message.sender,
    recipient: message.recipient,
    sessionId: message.sessionId,
    encryptedSessionKey: Buffer.from(message.encryptedSessionKey, 'base64'),
    recipientEncryptionKeyFingerprint: publicKeyFingerprint(idB.encryption.publicKey),
  });
  const signature = Buffer.from(message.signature, 'base64');
  assert.strictEqual(verify(idA.signing.publicKey, signedFor(1), signature), true);
  assert.strictEqual(verify(idA.signing.publicKey, signedFor(2), signature), false);
});

test('Attack 21: a signature from another private key fails', () => {
  const { message, verifyArgs } = freshKeyExchange();
  const signedData = canonicalizeHandshake({
    version: message.version,
    type: message.type,
    sender: message.sender,
    recipient: message.recipient,
    sessionId: message.sessionId,
    encryptedSessionKey: Buffer.from(message.encryptedSessionKey, 'base64'),
    recipientEncryptionKeyFingerprint: publicKeyFingerprint(idB.encryption.publicKey),
  });
  const forged = { ...message, signature: sign(idC.signing.privateKey, signedData).toString('base64') };
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(forged)), /Invalid signature/);
  // Signing with the (wrong-purpose) encryption key of A is not accepted either.
  const wrongPurpose = { ...message, signature: sign(idA.encryption.privateKey, signedData).toString('base64') };
  assertHandshakeError(() => verifyKeyExchange(verifyArgs(wrongPurpose)), /Invalid signature/);
});

test('Attack 22: the wrong recipient cannot accept the handshake', () => {
  const { message, verifyArgs } = freshKeyExchange();
  // C, addressed as itself, refuses a message meant for B.
  assertHandshakeError(
    () => verifyKeyExchange(verifyArgs(message, {
      expectedRecipient: 'Client C',
      ownEncryptionPublicKey: idC.encryption.publicKey,
      ownEncryptionPrivateKey: idC.encryption.privateKey,
    })),
    /not addressed/
  );
  // C pretending to be "Client B" with its own keys: the signature covers B's encryption-key
  // fingerprint, so it fails verification, and the ciphertext is undecryptable for C anyway.
  assertHandshakeError(
    () => verifyKeyExchange(verifyArgs(message, {
      ownEncryptionPublicKey: idC.encryption.publicKey,
      ownEncryptionPrivateKey: idC.encryption.privateKey,
    })),
    /Invalid signature/
  );
});

test('Attack 23: a replayed/duplicate handshake cannot overwrite an established session', () => {
  const { a, b, keyExchange, ack } = runHandshake(idA, idB);
  const keyBefore = Buffer.from(b.sessionKey);
  const idBefore = b.sessionId;

  // The identical KEY_EXCHANGE again:
  const replay = b.handleMessage(keyExchange);
  assert.ok(replay.error && /already established/.test(replay.error));
  assert.deepStrictEqual(replay.outgoing, []);
  // A different but perfectly valid KEY_EXCHANGE (new key, new ID) from the real A:
  const second = createKeyExchange({
    sender: 'Client A',
    recipient: 'Client B',
    signingPrivateKey: idA.signing.privateKey,
    peerEncryptionPublicKey: idB.encryption.publicKey,
  });
  assert.ok(b.handleMessage(second.message).error);
  // A duplicate HELLO and a duplicate ACK:
  assert.ok(b.handleMessage(helloOf(pemsA, 'Client A')).error);
  assert.ok(a.handleMessage(ack).error);

  assert.strictEqual(b.state, SESSION_STATES.ESTABLISHED);
  assert.ok(b.sessionKey.equals(keyBefore), 'session key unchanged');
  assert.strictEqual(b.sessionId, idBefore, 'session ID unchanged');
  assert.ok(a.sessionKey.equals(keyBefore), 'initiator side unchanged too');
});

// === ACK tests ================================================================

test('ACK: a valid signed acknowledgement verifies and carries no key material', () => {
  const sessionId = 'a'.repeat(32);
  const ack = createKeyExchangeAck({ sender: 'Client B', recipient: 'Client A', sessionId, signingPrivateKey: idB.signing.privateKey });
  assertValid(ack, 'ACK');
  assert.deepStrictEqual(Object.keys(ack), ['type', 'version', 'sender', 'recipient', 'sessionId', 'signature']);
  verifyKeyExchangeAck({ message: ack, expectedSender: 'Client B', expectedRecipient: 'Client A', expectedSessionId: sessionId, peerSigningPublicKey: idB.signing.publicKey });
});

test('ACK: tampered sender/recipient/sessionId, wrong session, or a foreign signer is rejected', () => {
  const sessionId = 'b'.repeat(32);
  const ack = createKeyExchangeAck({ sender: 'Client B', recipient: 'Client A', sessionId, signingPrivateKey: idB.signing.privateKey });
  const base = { expectedSender: 'Client B', expectedRecipient: 'Client A', expectedSessionId: sessionId, peerSigningPublicKey: idB.signing.publicKey };

  assertHandshakeError(() => verifyKeyExchangeAck({ ...base, message: { ...ack, sender: 'Client C' }, expectedSender: 'Client C' }), /Invalid signature/);
  assertHandshakeError(() => verifyKeyExchangeAck({ ...base, message: { ...ack, recipient: 'Client C' }, expectedRecipient: 'Client C' }), /Invalid signature/);
  assertHandshakeError(() => verifyKeyExchangeAck({ ...base, message: { ...ack, sessionId: 'c'.repeat(32) }, expectedSessionId: 'c'.repeat(32) }), /Invalid signature/);
  assertHandshakeError(() => verifyKeyExchangeAck({ ...base, message: ack, expectedSessionId: 'd'.repeat(32) }), /Unexpected session/);
  const foreign = createKeyExchangeAck({ sender: 'Client B', recipient: 'Client A', sessionId, signingPrivateKey: idC.signing.privateKey });
  assertHandshakeError(() => verifyKeyExchangeAck({ ...base, message: foreign }), /Invalid signature/);
});

test('ACK: a KEY_EXCHANGE signature cannot be reused as an ACK (type is signed)', () => {
  const { message } = freshKeyExchange();
  const asAck = { type: 'KEY_EXCHANGE_ACK', version: 1, sender: message.sender, recipient: message.recipient, sessionId: message.sessionId, signature: message.signature };
  assertHandshakeError(
    () => verifyKeyExchangeAck({ message: asAck, expectedSender: 'Client A', expectedRecipient: 'Client B', expectedSessionId: message.sessionId, peerSigningPublicKey: idA.signing.publicKey }),
    /Invalid signature/
  );
});

// === Canonicalization =========================================================

test('canonical: deterministic, independent of object key order, and boundary-unambiguous', () => {
  const ek = crypto.randomBytes(384);
  const fp = crypto.randomBytes(32);
  const fields = { version: 1, type: 'KEY_EXCHANGE', sender: 'Client A', recipient: 'Client B', sessionId: 'e'.repeat(32), encryptedSessionKey: ek, recipientEncryptionKeyFingerprint: fp };
  const reordered = { recipientEncryptionKeyFingerprint: fp, encryptedSessionKey: ek, sessionId: 'e'.repeat(32), recipient: 'Client B', sender: 'Client A', type: 'KEY_EXCHANGE', version: 1 };
  assert.ok(canonicalizeHandshake(fields).equals(canonicalizeHandshake(reordered)));
  assert.ok(canonicalizeHandshake(fields).equals(canonicalizeHandshake({ ...fields })));

  // ("Client Ab","Client B") must not collide with ("Client A","bClient B").
  const x = canonicalizeHandshake({ ...fields, sender: 'ab', recipient: 'c' });
  const y = canonicalizeHandshake({ ...fields, sender: 'a', recipient: 'bc' });
  assert.ok(!x.equals(y), 'length prefixes must keep field boundaries unambiguous');
  // Every field influences the output.
  for (const [field, value] of [['version', 2], ['type', 'KEY_EXCHANGE_ACK'], ['sender', 'Client C'], ['recipient', 'Client C'], ['sessionId', 'f'.repeat(32)]]) {
    const changed = field === 'type'
      ? canonicalizeHandshake({ version: 1, type: value, sender: 'Client A', recipient: 'Client B', sessionId: 'e'.repeat(32) })
      : canonicalizeHandshake({ ...fields, [field]: value });
    assert.ok(!changed.equals(canonicalizeHandshake(fields)), `${field} must be covered`);
  }
  assert.ok(!canonicalizeHandshake({ ...fields, encryptedSessionKey: crypto.randomBytes(384) }).equals(canonicalizeHandshake(fields)));
  assert.ok(!canonicalizeHandshake({ ...fields, recipientEncryptionKeyFingerprint: crypto.randomBytes(32) }).equals(canonicalizeHandshake(fields)));
});

test('canonical: rejects unsupported types and malformed inputs', () => {
  const base = { version: 1, sender: 'Client A', recipient: 'Client B', sessionId: 'a'.repeat(32) };
  assert.throws(() => canonicalizeHandshake({ ...base, type: 'CHAT' }), TypeError);
  assert.throws(() => canonicalizeHandshake({ ...base, type: 'KEY_EXCHANGE' }), TypeError, 'missing key fields');
  assert.throws(() => canonicalizeHandshake({ ...base, type: 'KEY_EXCHANGE_ACK', encryptedSessionKey: Buffer.alloc(1) }), TypeError);
  assert.throws(() => canonicalizeHandshake({ ...base, type: 'KEY_EXCHANGE_ACK', version: '1' }), TypeError);
  assert.throws(() => canonicalizeHandshake({ ...base, type: 'KEY_EXCHANGE_ACK', sender: '' }), TypeError);
});

// === KEY_EXCHANGE / ACK structural validation ================================

test('validation: malformed KEY_EXCHANGE / ACK messages are rejected', () => {
  const { message } = freshKeyExchange();
  assertValid(message, 'baseline');
  const cases = [
    [{ ...message, sessionId: 'XYZ' }, /sessionId/],
    [{ ...message, sessionId: 'A'.repeat(32) }, /sessionId/],
    [{ ...message, encryptedSessionKey: 'not base64!' }, /encryptedSessionKey/],
    [{ ...message, encryptedSessionKey: 'AAAA' }, /encryptedSessionKey/],
    [{ ...message, encryptedSessionKey: message.encryptedSessionKey.replace(/=*$/, '') + '=' }, /encryptedSessionKey/],
    [{ ...message, signature: '' }, /signature/],
    [{ ...message, signature: undefined }, /signature/],
    [{ ...message, recipient: message.sender }, /differ/],
    [{ ...message, recipient: '' }, /recipient/],
    [{ ...message, extra: 1 }, /unexpected field/],
    [{ ...message, version: 999 }, /version/],
  ];
  for (const [msg, pattern] of cases) assertInvalid(msg, JSON.stringify(Object.keys(msg)), pattern);
  const { encryptedSessionKey, ...ackShape } = { ...message, type: 'KEY_EXCHANGE_ACK' };
  assertValid(ackShape, 'ACK shape');
  assertInvalid({ ...ackShape, encryptedSessionKey }, 'ACK with a key field', /unexpected field/);
});

test('validation: SYSTEM presence events', () => {
  assertValid(createPeerEventMessage(PEER_EVENTS.PEER_JOINED, 'Client B', 'Client B has joined the chat.'), 'PEER_JOINED');
  assertValid(createPeerEventMessage(PEER_EVENTS.PEER_LEFT, 'Client B', 'Client B has disconnected.'), 'PEER_LEFT');
  assertValid(createSystemMessage('plain notice'), 'plain SYSTEM still valid');
  assertInvalid({ ...createSystemMessage('x'), event: 'NOPE', peer: 'Client B' }, 'unknown event', /event/);
  assertInvalid({ ...createSystemMessage('x'), event: 'PEER_LEFT' }, 'event without peer', /peer/);
});

// === Session state machine ====================================================

test('state machine: A initiates, B responds, states follow the documented path', () => {
  const a = new PeerSession({ selfId: 'Client A', identity: idA });
  const b = new PeerSession({ selfId: 'Client B', identity: idB });
  assert.strictEqual(a.state, SESSION_STATES.NO_SESSION);
  assert.strictEqual(a.sessionKey, null);
  assert.strictEqual(a.sessionKeyFingerprint(), null);

  const helloA = a.onPeerJoined().outgoing[0];
  const helloB = b.onPeerJoined().outgoing[0];
  assert.deepStrictEqual(a.onPeerJoined().outgoing, [], 'HELLO is sent only once');

  const bAfterHello = b.handleMessage(helloA);
  assert.strictEqual(b.state, SESSION_STATES.HELLO_EXCHANGED);
  assert.deepStrictEqual(bAfterHello.outgoing, [], 'the responder never initiates');

  const aAfterHello = a.handleMessage(helloB);
  assert.strictEqual(a.state, SESSION_STATES.KEY_SENT);
  assert.strictEqual(aAfterHello.event, 'KEY_EXCHANGE_SENT');
  assert.strictEqual(a.sessionKey, null, 'an unconfirmed key is not exposed');

  const bAfterKey = b.handleMessage(aAfterHello.outgoing[0]);
  assert.strictEqual(b.state, SESSION_STATES.ESTABLISHED);
  assert.strictEqual(bAfterKey.event, 'ESTABLISHED');
  assert.strictEqual(bAfterKey.outgoing[0].type, 'KEY_EXCHANGE_ACK');

  assert.strictEqual(a.handleMessage(bAfterKey.outgoing[0]).event, 'ESTABLISHED');
  assert.strictEqual(a.state, SESSION_STATES.ESTABLISHED);
});

test('state machine: the initiator sends its own HELLO before KEY_EXCHANGE even if the peer\'s HELLO arrives first', () => {
  const a = new PeerSession({ selfId: 'Client A', identity: idA });
  const result = a.handleMessage(helloOf(pemsB, 'Client B')); // no onPeerJoined() yet
  assert.deepStrictEqual(result.outgoing.map((m) => m.type), ['HELLO', 'KEY_EXCHANGE']);
});

test('state machine: out-of-order and role-violating messages are rejected without state change', () => {
  const { message } = freshKeyExchange();
  const b = new PeerSession({ selfId: 'Client B', identity: idB });
  assert.ok(b.handleMessage(message).error, 'KEY_EXCHANGE before HELLO');
  assert.strictEqual(b.state, SESSION_STATES.NO_SESSION);

  const a = new PeerSession({ selfId: 'Client A', identity: idA });
  a.handleMessage(helloOf(pemsB, 'Client B'));
  assert.ok(a.handleMessage(message).error, 'the initiator never accepts KEY_EXCHANGE');
  assert.strictEqual(a.state, SESSION_STATES.KEY_SENT);
  const ack = createKeyExchangeAck({ sender: 'Client B', recipient: 'Client A', sessionId: 'a'.repeat(32), signingPrivateKey: idB.signing.privateKey });
  assert.ok(new PeerSession({ selfId: 'Client B', identity: idB }).handleMessage(ack).error, 'the responder never accepts an ACK');
  assert.ok(a.handleMessage({ type: 'CHAT', text: 'hi' }).error, 'non-handshake type');
});

test('state machine: a failed verification moves to FAILED and exposes no key', () => {
  const a = new PeerSession({ selfId: 'Client A', identity: idA });
  const b = new PeerSession({ selfId: 'Client B', identity: idB });
  b.handleMessage(a.onPeerJoined().outgoing[0]);
  const exchange = a.handleMessage(helloOf(pemsB, 'Client B')).outgoing.find((m) => m.type === 'KEY_EXCHANGE');

  const result = b.handleMessage({ ...exchange, encryptedSessionKey: flipBase64Byte(exchange.encryptedSessionKey, 3) });
  assert.strictEqual(result.error, 'Invalid signature.');
  assert.deepStrictEqual(result.outgoing, [], 'no ACK for a rejected handshake');
  assert.strictEqual(b.state, SESSION_STATES.FAILED);
  assert.strictEqual(b.sessionKey, null);
  assert.ok(b.handleMessage(exchange).error, 'FAILED is sticky: even the genuine message is now refused');

  // A rejects a bad ACK too (signed by the wrong key) and fails.
  const badAck = createKeyExchangeAck({ sender: 'Client B', recipient: 'Client A', sessionId: exchange.sessionId, signingPrivateKey: idC.signing.privateKey });
  assert.strictEqual(a.handleMessage(badAck).error, 'Invalid signature.');
  assert.strictEqual(a.state, SESSION_STATES.FAILED);
  assert.strictEqual(a.sessionKey, null);
});

test('state machine: peer-left clears the session; a new handshake yields a new key and session ID', () => {
  const first = runHandshake(idA, idB);
  const oldKey = Buffer.from(first.a.sessionKey);
  const oldId = first.a.sessionId;

  first.a.onPeerLeft();
  assert.strictEqual(first.a.state, SESSION_STATES.NO_SESSION);
  assert.strictEqual(first.a.sessionKey, null);
  assert.strictEqual(first.a.sessionId, null);
  assert.strictEqual(first.a.peerSigningPublicKey, null);

  const idB2 = createIdentity(); // a new peer joins with fresh keys
  const b2 = new PeerSession({ selfId: 'Client B', identity: idB2 });
  const helloA = first.a.onPeerJoined().outgoing[0];
  assert.ok(helloA, 'HELLO can be sent again after a reset');
  const helloB2 = b2.handleMessage(helloA).outgoing[0]; // B's HELLO is always emitted before anything else
  assert.strictEqual(helloB2.type, 'HELLO');
  assert.deepStrictEqual(b2.onPeerJoined().outgoing, [], 'and is never sent twice');
  const exchange = first.a.handleMessage(helloB2).outgoing.find((m) => m.type === 'KEY_EXCHANGE');
  first.a.handleMessage(b2.handleMessage(exchange).outgoing[0]);

  assert.strictEqual(first.a.state, SESSION_STATES.ESTABLISHED);
  assert.ok(first.a.sessionKey.equals(b2.sessionKey));
  assert.ok(!first.a.sessionKey.equals(oldKey));
  assert.notStrictEqual(first.a.sessionId, oldId);
});

test('state machine: only the two known identities are valid', () => {
  assert.throws(() => new PeerSession({ selfId: 'Client C', identity: idA }), TypeError);
  assert.throws(() => new PeerSession({ selfId: undefined, identity: idA }), TypeError);
});

// === Fingerprints and hygiene =================================================

test('fingerprints: short, diagnostic, deterministic, and not the key', () => {
  const key = crypto.randomBytes(32);
  const fingerprint = sessionKeyFingerprint(key);
  assert.ok(/^[0-9a-f]{8}\.\.\.[0-9a-f]{8}$/.test(fingerprint));
  assert.strictEqual(fingerprint, sessionKeyFingerprint(Buffer.from(key)));
  assert.notStrictEqual(fingerprint, sessionKeyFingerprint(crypto.randomBytes(32)));
  const digest = crypto.createHash('sha256').update(key).digest('hex');
  assert.strictEqual(fingerprint, `${digest.slice(0, 8)}...${digest.slice(-8)}`);
  assert.ok(!fingerprint.includes(key.toString('hex').slice(0, 8)));
  assert.throws(() => sessionKeyFingerprint(Buffer.alloc(31)), TypeError);
  assert.throws(() => sessionKeyFingerprint('a string'), TypeError);

  const pub = publicKeyFingerprint(idA.encryption.publicKey);
  assert.strictEqual(pub.length, 32);
  assert.ok(!pub.equals(publicKeyFingerprint(idA.signing.publicKey)));
});

test('identity: two distinct key pairs per client; only public halves are exportable', () => {
  assert.ok(!idA.encryption.publicKey.equals(idA.signing.publicKey));
  assert.ok(!idA.encryption.privateKey.equals(idA.signing.privateKey));
  assert.deepStrictEqual(Object.keys(pemsA), ['encryptionPublicKey', 'signingPublicKey']);
  for (const pem of Object.values(pemsA)) assert.ok(pem.startsWith('-----BEGIN PUBLIC KEY-----'));
});

test('security sources never log, never use Math.random, and reuse (not re-implement) the crypto primitives', () => {
  const dir = path.join(__dirname, '..', 'src', 'security');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js'));
  assert.ok(files.length >= 3);
  for (const file of files) {
    const code = fs.readFileSync(path.join(dir, file), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.ok(!/console\./.test(code), `${file} must not log`);
    assert.ok(!/Math\.random/.test(code), `${file} must not use Math.random`);
    assert.ok(!/require\(['"]crypto['"]\)/.test(code), `${file} must use src/crypto, not node:crypto directly`);
  }
  const canonical = fs.readFileSync(path.join(__dirname, '..', 'src', 'protocol', 'canonical.js'), 'utf8');
  assert.ok(!/require\(['"]crypto['"]\)/.test(canonical), 'canonical.js only builds bytes');
});

console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
