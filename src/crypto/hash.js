'use strict';

/**
 * SHA-256 helpers (Node's crypto.createHash - nothing custom).
 *
 * Fingerprints here are IDENTIFIERS/DIAGNOSTICS, never keys:
 *   - publicKeyFingerprint: SHA-256 over the SPKI DER encoding of a public
 *     key. Used to bind a handshake to the exact recipient key.
 *   - sessionKeyFingerprint: a short display form of SHA-256(sessionKey) so
 *     two clients can confirm they hold the same key WITHOUT printing it.
 *     Diagnostic only: do not use it as a key, password or secret.
 */

const crypto = require('crypto');
const { assertRsaPublicKey } = require('./keys');
const { SESSION_KEY_BYTES } = require('./session');

function sha256(data) {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('data must be a Buffer or Uint8Array.');
  }
  return crypto.createHash('sha256').update(data).digest();
}

/** @returns {Buffer} 32-byte SHA-256 of the key's SPKI DER encoding */
function publicKeyFingerprint(publicKey) {
  assertRsaPublicKey(publicKey);
  return sha256(publicKey.export({ type: 'spki', format: 'der' }));
}

/** @returns {string} e.g. "a83f12c9...5e91c2d0" (first and last 8 hex chars of SHA-256(key)) */
function sessionKeyFingerprint(sessionKey) {
  if (!(sessionKey instanceof Uint8Array) || sessionKey.length !== SESSION_KEY_BYTES) {
    throw new TypeError(`sessionKey must be exactly ${SESSION_KEY_BYTES} bytes.`);
  }
  const hex = sha256(sessionKey).toString('hex');
  return `${hex.slice(0, 8)}...${hex.slice(-8)}`;
}

module.exports = {
  sha256,
  publicKeyFingerprint,
  sessionKeyFingerprint,
};
