'use strict';

/**
 * Canonical (deterministic) byte encoding of the handshake data that gets
 * signed. This is protocol serialization, kept separate from the crypto
 * primitives: it only builds bytes; src/crypto/signing.js signs them.
 *
 * Why not JSON.stringify: JSON text is not canonical (key order, spacing,
 * escaping), so signer and verifier could disagree, or two different
 * messages could share one signed byte string. Instead every field is
 * encoded as
 *
 *     uint32 big-endian byte length  ||  field bytes
 *
 * in a FIXED order. Length prefixes make field boundaries unambiguous
 * (("ab","c") and ("a","bc") produce different bytes), and the message
 * type is inside the signed data, so a signature for one message type can
 * never be presented as another.
 *
 * Signed layout (all length-prefixed):
 *   KEY_EXCHANGE:     label, version, type, sender, recipient, sessionId,
 *                     encryptedSessionKey (raw bytes),
 *                     recipientEncryptionKeyFingerprint (raw 32 bytes)
 *   KEY_EXCHANGE_ACK: label, version, type, sender, recipient, sessionId
 *
 * recipientEncryptionKeyFingerprint = SHA-256 of the recipient's encryption
 * public key (SPKI DER). The verifier computes it from ITS OWN key, so a
 * ciphertext wrapped for any other key fails signature verification. It is
 * not sent on the wire.
 */

const { MESSAGE_TYPES } = require('./message');

const SIGNATURE_LABEL = 'CipherLink handshake signature';

function lengthPrefixed(value) {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Canonical field must be a string or bytes.');
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([prefix, bytes]);
}

function requireNonEmptyString(name, value) {
  if (typeof value !== 'string' || value === '') {
    throw new TypeError(`Canonical field "${name}" must be a non-empty string.`);
  }
}

/**
 * @param {object} fields
 * @param {number} fields.version
 * @param {string} fields.type KEY_EXCHANGE or KEY_EXCHANGE_ACK
 * @param {string} fields.sender
 * @param {string} fields.recipient
 * @param {string} fields.sessionId
 * @param {Buffer} [fields.encryptedSessionKey] KEY_EXCHANGE only
 * @param {Buffer} [fields.recipientEncryptionKeyFingerprint] KEY_EXCHANGE only
 * @returns {Buffer} the exact bytes to sign / verify
 */
function canonicalizeHandshake(fields) {
  const { version, type, sender, recipient, sessionId, encryptedSessionKey, recipientEncryptionKeyFingerprint } = fields;

  if (!Number.isInteger(version) || version < 0) {
    throw new TypeError('Canonical field "version" must be a non-negative integer.');
  }
  requireNonEmptyString('type', type);
  requireNonEmptyString('sender', sender);
  requireNonEmptyString('recipient', recipient);
  requireNonEmptyString('sessionId', sessionId);

  const parts = [
    lengthPrefixed(SIGNATURE_LABEL),
    lengthPrefixed(String(version)),
    lengthPrefixed(type),
    lengthPrefixed(sender),
    lengthPrefixed(recipient),
    lengthPrefixed(sessionId),
  ];

  if (type === MESSAGE_TYPES.KEY_EXCHANGE) {
    if (!(encryptedSessionKey instanceof Uint8Array) || !(recipientEncryptionKeyFingerprint instanceof Uint8Array)) {
      throw new TypeError('KEY_EXCHANGE requires encryptedSessionKey and recipientEncryptionKeyFingerprint bytes.');
    }
    parts.push(lengthPrefixed(encryptedSessionKey), lengthPrefixed(recipientEncryptionKeyFingerprint));
  } else if (type === MESSAGE_TYPES.KEY_EXCHANGE_ACK) {
    if (encryptedSessionKey !== undefined || recipientEncryptionKeyFingerprint !== undefined) {
      throw new TypeError('KEY_EXCHANGE_ACK has no key fields.');
    }
  } else {
    throw new TypeError(`Cannot canonicalize message type "${type}".`);
  }

  return Buffer.concat(parts);
}

module.exports = {
  SIGNATURE_LABEL,
  canonicalizeHandshake,
};
