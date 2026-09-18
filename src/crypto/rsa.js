'use strict';

/**
 * RSA-OAEP (SHA-256) encryption/decryption.
 *
 * Intended future use: wrapping a 32-byte AES session key for a
 * recipient. It is NOT for encrypting chat text - RSA can only handle
 * data smaller than the modulus (318 bytes max with a 3072-bit key and
 * SHA-256 OAEP), and AES will carry the actual messages.
 *
 * What Node does here:
 *   crypto.publicEncrypt / crypto.privateDecrypt with
 *     padding  = RSA_PKCS1_OAEP_PADDING  (RSAES-OAEP, RFC 8017)
 *     oaepHash = 'sha256'                (used for OAEP *and* MGF1 per Node docs)
 *     label    = empty (Node does not set one)
 *   OAEP inserts fresh random seed bytes on every encryption, so
 *   encrypting the same plaintext twice gives different ciphertexts.
 *
 * Error policy: every decryption failure (wrong key, corrupted
 * ciphertext, wrong length, bad padding) throws the same fixed error, so
 * a caller/attacker cannot distinguish failure causes. The error never
 * contains key material or plaintext.
 */

const crypto = require('crypto');
const { assertRsaPublicKey, assertRsaPrivateKey } = require('./keys');

const OAEP_HASH = 'sha256';
const OAEP_HASH_BYTES = 32;

function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Buffer or Uint8Array.`);
  }
}

/** Largest plaintext (in bytes) that RSA-OAEP-SHA256 can encrypt with this key: k - 2*hLen - 2. */
function maxPlaintextLength(publicKey) {
  assertRsaPublicKey(publicKey);
  return publicKey.asymmetricKeyDetails.modulusLength / 8 - 2 * OAEP_HASH_BYTES - 2;
}

/**
 * @param {crypto.KeyObject} publicKey recipient's RSA public key
 * @param {Buffer|Uint8Array} plaintext non-empty, at most maxPlaintextLength(publicKey) bytes
 * @returns {Buffer} ciphertext, exactly modulus-size bytes
 */
function rsaEncrypt(publicKey, plaintext) {
  assertRsaPublicKey(publicKey);
  assertBytes(plaintext, 'plaintext');
  if (plaintext.length === 0) {
    throw new RangeError('plaintext must not be empty.');
  }
  if (plaintext.length > maxPlaintextLength(publicKey)) {
    throw new RangeError('plaintext is too long for RSA-OAEP with this key.');
  }
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: OAEP_HASH,
    },
    plaintext
  );
}

/**
 * @param {crypto.KeyObject} privateKey recipient's RSA private key
 * @param {Buffer|Uint8Array} ciphertext output of rsaEncrypt
 * @returns {Buffer} the original plaintext
 * @throws {Error} 'RSA-OAEP decryption failed.' for any ciphertext problem
 */
function rsaDecrypt(privateKey, ciphertext) {
  assertRsaPrivateKey(privateKey);
  assertBytes(ciphertext, 'ciphertext');
  try {
    return crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: OAEP_HASH,
      },
      ciphertext
    );
  } catch (err) {
    throw new Error('RSA-OAEP decryption failed.');
  }
}

module.exports = {
  OAEP_HASH,
  maxPlaintextLength,
  rsaEncrypt,
  rsaDecrypt,
};
