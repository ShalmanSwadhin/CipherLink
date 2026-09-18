'use strict';

/**
 * Session secrets: AES-256 session keys and session IDs.
 *
 * Only *generates* random values. No AES encryption/decryption exists yet
 * (that is a later phase, planned as AES-256-GCM).
 *
 * Both come from crypto.randomBytes(), Node's CSPRNG (OpenSSL RAND_bytes,
 * seeded by the operating system).
 *
 * Session KEYS are secret: never log them, never send them unencrypted,
 * never give them to the server. They travel only inside RSA-OAEP.
 * Session IDs are public identifiers (they are sent in the clear and signed).
 */

const crypto = require('crypto');

const SESSION_KEY_BYTES = 32; // 256 bits
const SESSION_ID_BYTES = 16; // 128 bits, hex-encoded to 32 characters

/** @returns {Buffer} 32 cryptographically secure random bytes */
function generateSessionKey() {
  return crypto.randomBytes(SESSION_KEY_BYTES);
}

/** @returns {string} 32 lowercase hex characters (128 random bits) */
function generateSessionId() {
  return crypto.randomBytes(SESSION_ID_BYTES).toString('hex');
}

module.exports = {
  SESSION_KEY_BYTES,
  SESSION_ID_BYTES,
  generateSessionKey,
  generateSessionId,
};
