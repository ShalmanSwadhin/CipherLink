'use strict';

/**
 * Unit tests for src/crypto/* - the primitives are tested on their own,
 * with no networking and no chat protocol involved.
 * Run with: npm test
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const {
  RSA_MODULUS_LENGTH,
  generateKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
} = require('../src/crypto/keys');
const { rsaEncrypt, rsaDecrypt, maxPlaintextLength } = require('../src/crypto/rsa');
const { sign, verify } = require('../src/crypto/signing');
const { SESSION_KEY_BYTES, generateSessionKey } = require('../src/crypto/session');

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

function flipBit(buf, index) {
  const copy = Buffer.from(buf);
  copy[index] ^= 0x01;
  return copy;
}

console.log('Running crypto unit tests (generating RSA-3072 keys, this takes a moment)...');

const keyPairA = generateKeyPair();
const keyPairB = generateKeyPair();
// Weak/non-RSA keys exist only to prove they are refused.
const weakPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ecPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

const MESSAGE = Buffer.from('CipherLink protocol data to sign');

// --- RSA key generation -----------------------------------------------------

test('Test 1: generates an RSA-3072 key pair', () => {
  assert.strictEqual(RSA_MODULUS_LENGTH, 3072);
  assert.strictEqual(keyPairA.publicKey.type, 'public');
  assert.strictEqual(keyPairA.privateKey.type, 'private');
  assert.strictEqual(keyPairA.publicKey.asymmetricKeyType, 'rsa');
  assert.strictEqual(keyPairA.publicKey.asymmetricKeyDetails.modulusLength, 3072);
  assert.strictEqual(keyPairA.publicKey.asymmetricKeyDetails.publicExponent, 65537n);
  assert.ok(!keyPairA.publicKey.equals(keyPairB.publicKey), 'two generated pairs must differ');
});

test('Test 2: keys export to standard PEM and import back identically', () => {
  const pubPem = exportPublicKey(keyPairA.publicKey);
  const privPem = exportPrivateKey(keyPairA.privateKey);
  assert.ok(pubPem.startsWith('-----BEGIN PUBLIC KEY-----'), 'public key should be SPKI PEM');
  assert.ok(privPem.startsWith('-----BEGIN PRIVATE KEY-----'), 'private key should be PKCS#8 PEM');
  assert.ok(importPublicKey(pubPem).equals(keyPairA.publicKey));
  assert.ok(importPrivateKey(privPem).equals(keyPairA.privateKey));
});

test('Test 3: imported keys still work for OAEP and PSS', () => {
  const pub = importPublicKey(exportPublicKey(keyPairA.publicKey));
  const priv = importPrivateKey(exportPrivateKey(keyPairA.privateKey));
  const secret = generateSessionKey();
  assert.ok(rsaDecrypt(priv, rsaEncrypt(pub, secret)).equals(secret));
  assert.strictEqual(verify(pub, MESSAGE, sign(priv, MESSAGE)), true);
});

// --- RSA-OAEP ---------------------------------------------------------------

test('Test 4: OAEP round trip returns the original plaintext (32-byte session key)', () => {
  const sessionKey = generateSessionKey();
  const ciphertext = rsaEncrypt(keyPairA.publicKey, sessionKey);
  assert.strictEqual(ciphertext.length, 384, 'ciphertext is one modulus (3072 bits = 384 bytes)');
  assert.ok(!ciphertext.includes(sessionKey), 'ciphertext must not contain the plaintext');
  assert.ok(rsaDecrypt(keyPairA.privateKey, ciphertext).equals(sessionKey));
});

test('Test 4b: OAEP handles the maximum plaintext size, and rejects one byte more', () => {
  const max = maxPlaintextLength(keyPairA.publicKey);
  assert.strictEqual(max, 318);
  const biggest = crypto.randomBytes(max);
  assert.ok(rsaDecrypt(keyPairA.privateKey, rsaEncrypt(keyPairA.publicKey, biggest)).equals(biggest));
  assert.throws(() => rsaEncrypt(keyPairA.publicKey, crypto.randomBytes(max + 1)), RangeError);
});

test('Test 5: the wrong private key cannot decrypt', () => {
  const ciphertext = rsaEncrypt(keyPairA.publicKey, generateSessionKey());
  assert.throws(() => rsaDecrypt(keyPairB.privateKey, ciphertext), /decryption failed/);
});

test('Test 6: modified ciphertext fails to decrypt', () => {
  const ciphertext = rsaEncrypt(keyPairA.publicKey, generateSessionKey());
  for (const index of [0, 1, 100, 200, ciphertext.length - 1]) {
    assert.throws(() => rsaDecrypt(keyPairA.privateKey, flipBit(ciphertext, index)), /decryption failed/, `bit flip at byte ${index}`);
  }
});

test('Test 7: encrypting the same plaintext twice gives different ciphertexts (both decrypt)', () => {
  const plaintext = generateSessionKey();
  const c1 = rsaEncrypt(keyPairA.publicKey, plaintext);
  const c2 = rsaEncrypt(keyPairA.publicKey, plaintext);
  assert.ok(!c1.equals(c2), 'OAEP must be randomized');
  assert.ok(rsaDecrypt(keyPairA.privateKey, c1).equals(plaintext));
  assert.ok(rsaDecrypt(keyPairA.privateKey, c2).equals(plaintext));
});

// --- RSA-PSS ----------------------------------------------------------------

test('Test 8: a signature verifies', () => {
  const signature = sign(keyPairA.privateKey, MESSAGE);
  assert.strictEqual(signature.length, 384);
  assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, signature), true);
});

test('Test 9: modified data fails verification', () => {
  const signature = sign(keyPairA.privateKey, MESSAGE);
  assert.strictEqual(verify(keyPairA.publicKey, flipBit(MESSAGE, 0), signature), false);
  assert.strictEqual(verify(keyPairA.publicKey, Buffer.concat([MESSAGE, Buffer.from('!')]), signature), false);
});

test('Test 10: modified signature fails verification', () => {
  const signature = sign(keyPairA.privateKey, MESSAGE);
  for (const index of [0, 100, signature.length - 1]) {
    assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, flipBit(signature, index)), false, `bit flip at byte ${index}`);
  }
});

test('Test 11: a signature from another private key fails verification', () => {
  const signatureByB = sign(keyPairB.privateKey, MESSAGE);
  assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, signatureByB), false);
  assert.strictEqual(verify(keyPairB.publicKey, MESSAGE, signatureByB), true, 'sanity: B\'s own key does verify it');
});

test('Test 12: signing the same data twice gives different signatures (both valid)', () => {
  const s1 = sign(keyPairA.privateKey, MESSAGE);
  const s2 = sign(keyPairA.privateKey, MESSAGE);
  assert.ok(!s1.equals(s2), 'PSS must be randomized');
  assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, s1), true);
  assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, s2), true);
});

// --- AES-256 session keys ---------------------------------------------------

test('Test 13: a session key is exactly 32 bytes (256 bits)', () => {
  const key = generateSessionKey();
  assert.ok(Buffer.isBuffer(key));
  assert.strictEqual(SESSION_KEY_BYTES, 32);
  assert.strictEqual(key.length, 32);
});

test('Test 14: generated session keys are not identical', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) {
    seen.add(generateSessionKey().toString('hex'));
  }
  assert.strictEqual(seen.size, 1000);
  assert.ok(!generateSessionKey().equals(Buffer.alloc(32)), 'must not be all zeros');
});

test('Test 15: a generated key is a valid 256-bit AES key length', () => {
  const key = generateSessionKey();
  const secret = crypto.createSecretKey(key);
  assert.strictEqual(secret.type, 'secret');
  assert.strictEqual(secret.symmetricKeySize, 32);
  assert.strictEqual(crypto.getCipherInfo('aes-256-gcm').keyLength, key.length);
});

// --- Negative / error handling: keys ----------------------------------------

test('key import rejects garbage, wrong types and mismatched PEM kinds', () => {
  for (const bad of ['', 'not a pem', null, undefined, 42, {}, Buffer.from('x')]) {
    assert.throws(() => importPublicKey(bad), /public key/i);
    assert.throws(() => importPrivateKey(bad), /private key/i);
  }
  // A private-key PEM is not accepted as a public key, and vice versa.
  assert.throws(() => importPublicKey(exportPrivateKey(keyPairA.privateKey)));
  assert.throws(() => importPrivateKey(exportPublicKey(keyPairA.publicKey)));
});

test('private-key import errors do not leak key material', () => {
  const pem = exportPrivateKey(keyPairA.privateKey);
  const lines = pem.trim().split('\n');
  const bodyLines = lines.slice(1, -1);
  const last = lines[lines.length - 1];
  const truncated = [lines[0], ...bodyLines.slice(0, 10), last].join('\n');
  const badHeader = [lines[0], 'AAAA' + bodyLines[0].slice(4), ...bodyLines.slice(1), last].join('\n');
  for (const corrupted of [truncated, badHeader]) {
    let thrown;
    try {
      importPrivateKey(corrupted);
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown, 'structurally broken private key must be rejected');
    assert.strictEqual(thrown.message, 'Invalid private key PEM.');
    const text = `${thrown.message}\n${thrown.stack}`;
    for (const line of bodyLines) {
      assert.ok(!text.includes(line), 'error output must not contain private key PEM data');
    }
  }
});

test('weak (2048-bit) and non-RSA keys are refused everywhere', () => {
  const weakPubPem = weakPair.publicKey.export({ type: 'spki', format: 'pem' });
  const weakPrivPem = weakPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => importPublicKey(weakPubPem), RangeError);
  assert.throws(() => importPrivateKey(weakPrivPem), RangeError);
  assert.throws(() => rsaEncrypt(weakPair.publicKey, generateSessionKey()), RangeError);
  assert.throws(() => sign(weakPair.privateKey, MESSAGE), RangeError);
  assert.throws(() => exportPublicKey(weakPair.publicKey), RangeError);

  assert.throws(() => rsaEncrypt(ecPair.publicKey, generateSessionKey()), TypeError);
  assert.throws(() => sign(ecPair.privateKey, MESSAGE), TypeError);
});

test('export/encrypt/sign reject the wrong kind of key or non-key values', () => {
  assert.throws(() => exportPublicKey(keyPairA.privateKey), TypeError);
  assert.throws(() => exportPrivateKey(keyPairA.publicKey), TypeError);
  assert.throws(() => rsaEncrypt(keyPairA.privateKey, generateSessionKey()), TypeError);
  assert.throws(() => rsaDecrypt(keyPairA.publicKey, Buffer.alloc(384)), TypeError);
  assert.throws(() => sign(keyPairA.publicKey, MESSAGE), TypeError);
  assert.throws(() => verify(keyPairA.privateKey, MESSAGE, Buffer.alloc(384)), TypeError);
  const pem = exportPublicKey(keyPairA.publicKey);
  for (const notAKey of [pem, null, undefined, 123, {}]) {
    assert.throws(() => rsaEncrypt(notAKey, generateSessionKey()), TypeError);
    assert.throws(() => sign(notAKey, MESSAGE), TypeError);
    assert.throws(() => verify(notAKey, MESSAGE, Buffer.alloc(384)), TypeError);
  }
});

// --- Negative / error handling: OAEP ----------------------------------------

test('rsaEncrypt rejects invalid plaintext types and empty plaintext', () => {
  for (const bad of ['a string', 42, null, undefined, {}, [1, 2, 3]]) {
    assert.throws(() => rsaEncrypt(keyPairA.publicKey, bad), TypeError);
  }
  assert.throws(() => rsaEncrypt(keyPairA.publicKey, Buffer.alloc(0)), RangeError);
});

test('rsaDecrypt fails safely and uniformly on invalid ciphertext', () => {
  const good = rsaEncrypt(keyPairA.publicKey, generateSessionKey());
  const failures = [
    Buffer.alloc(0),
    Buffer.alloc(384), // all zeros
    crypto.randomBytes(384), // random garbage
    good.subarray(0, 383), // truncated
    Buffer.concat([good, Buffer.from([0])]), // extended
  ];
  for (const bad of failures) {
    assert.throws(() => rsaDecrypt(keyPairA.privateKey, bad), (err) => err.message === 'RSA-OAEP decryption failed.');
  }
  // Wrong key and tampering produce the identical error (no failure-cause oracle).
  let wrongKeyMessage;
  let tamperedMessage;
  try { rsaDecrypt(keyPairB.privateKey, good); } catch (err) { wrongKeyMessage = err.message; }
  try { rsaDecrypt(keyPairA.privateKey, flipBit(good, 10)); } catch (err) { tamperedMessage = err.message; }
  assert.strictEqual(wrongKeyMessage, tamperedMessage);

  for (const bad of ['a string', 42, null, undefined, {}]) {
    assert.throws(() => rsaDecrypt(keyPairA.privateKey, bad), TypeError);
  }
});

// --- Negative / error handling: PSS -----------------------------------------

test('sign rejects invalid data types and empty data', () => {
  for (const bad of ['a string', 42, null, undefined, {}, [1, 2, 3]]) {
    assert.throws(() => sign(keyPairA.privateKey, bad), TypeError);
  }
  assert.throws(() => sign(keyPairA.privateKey, Buffer.alloc(0)), RangeError);
});

test('verify returns false (never throws) for bad signatures and empty data', () => {
  const good = sign(keyPairA.privateKey, MESSAGE);
  const badSignatures = [
    Buffer.alloc(0),
    Buffer.alloc(384),
    crypto.randomBytes(384),
    good.subarray(0, 383),
    Buffer.concat([good, Buffer.from([0])]),
    Buffer.from('not a signature'),
  ];
  for (const bad of badSignatures) {
    assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, bad), false);
  }
  assert.strictEqual(verify(keyPairA.publicKey, Buffer.alloc(0), good), false);
});

test('verify throws TypeError for wrong argument types', () => {
  const good = sign(keyPairA.privateKey, MESSAGE);
  for (const bad of ['a string', 42, null, undefined, {}]) {
    assert.throws(() => verify(keyPairA.publicKey, bad, good), TypeError);
    assert.throws(() => verify(keyPairA.publicKey, MESSAGE, bad), TypeError);
  }
});

test('a PSS signature cannot be reinterpreted under different signing parameters', () => {
  // Signed with a different (non-digest) salt length => must not verify with our strict verifier.
  const signature = crypto.sign('sha256', MESSAGE, {
    key: keyPairA.privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 20,
  });
  assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, signature), false);
  // Signed with PKCS#1 v1.5 padding => also rejected.
  const v15 = crypto.sign('sha256', MESSAGE, keyPairA.privateKey);
  assert.strictEqual(verify(keyPairA.publicKey, MESSAGE, v15), false);
});

// --- Scope / hygiene guards -------------------------------------------------

test('crypto sources never log and never use Math.random', () => {
  const dir = path.join(__dirname, '..', 'src', 'crypto');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js'));
  assert.ok(files.length >= 4);
  for (const file of files) {
    const code = fs.readFileSync(path.join(dir, file), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.ok(!/console\./.test(code), `${file} must not log`);
    assert.ok(!/Math\.random/.test(code), `${file} must not use Math.random`);
    assert.ok(!/ecb/i.test(code), `${file} must not reference ECB`);
  }
});

test('the relay server stays crypto-free; protocol only uses public-key validation', () => {
  // Phase 4 integrates the primitives into the CLIENT (via src/security). The server must
  // remain a pure relay, and the protocol layer may only import crypto/keys (public-key checks).
  const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
  const server = read('src/server.js').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.ok(!/require\(['"]crypto['"]\)/.test(server), 'server.js must not require node:crypto');
  assert.ok(!/require\(['"]\.\/(crypto|security)\//.test(server), 'server.js must not require crypto/security modules');
  assert.ok(!/privateKey|rsaDecrypt|rsaEncrypt|generateSessionKey|sign\(/.test(server), 'server.js must not touch keys or signing');

  const message = read('src/protocol/message.js');
  assert.ok(!/require\(['"]crypto['"]\)/.test(message), 'message.js must not require node:crypto');
  const cryptoImports = [...message.matchAll(/require\(['"]\.\.\/crypto\/([\w-]+)['"]\)/g)].map((m) => m[1]);
  assert.deepStrictEqual(cryptoImports, ['keys'], 'message.js may only import crypto/keys');
});

console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
