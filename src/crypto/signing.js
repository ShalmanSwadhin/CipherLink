'use strict';

/**
 * RSA-PSS signatures with SHA-256.
 *
 * What Node does here (crypto.sign / crypto.verify with algorithm 'sha256'):
 *   1. Node hashes `data` with SHA-256 itself - we do NOT pre-hash.
 *   2. The digest is encoded with RSASSA-PSS (RFC 8017): a random salt is
 *      mixed in, and MGF1 uses the same digest (SHA-256).
 *   3. The result is signed with the private key.
 *   padding    = RSA_PKCS1_PSS_PADDING
 *   saltLength = RSA_PSS_SALTLEN_DIGEST (32 bytes = SHA-256 output size)
 *   Verification uses the same explicit parameters, so a signature made
 *   with a different salt length is rejected rather than silently accepted.
 *
 * Because of the random salt, signing the same data twice gives different
 * signatures; both verify.
 *
 * Contract:
 *   - sign() throws on invalid keys/inputs (programming errors).
 *   - verify() throws only on an invalid *key* or wrong argument types.
 *     For anything that could come from an attacker (tampered data,
 *     garbage/truncated/empty signature, signature from another key) it
 *     returns false and never throws.
 */

const crypto = require('crypto');
const { assertRsaPublicKey, assertRsaPrivateKey } = require('./keys');

const SIGNATURE_HASH = 'sha256';
const PSS_SALT_LENGTH = crypto.constants.RSA_PSS_SALTLEN_DIGEST;

function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Buffer or Uint8Array.`);
  }
}

function pssOptions(key) {
  return {
    key,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: PSS_SALT_LENGTH,
  };
}

/**
 * @param {crypto.KeyObject} privateKey signer's RSA private key
 * @param {Buffer|Uint8Array} data non-empty bytes to sign
 * @returns {Buffer} signature, exactly modulus-size bytes
 */
function sign(privateKey, data) {
  assertRsaPrivateKey(privateKey);
  assertBytes(data, 'data');
  if (data.length === 0) {
    throw new RangeError('data must not be empty.');
  }
  return crypto.sign(SIGNATURE_HASH, data, pssOptions(privateKey));
}

/**
 * @param {crypto.KeyObject} publicKey signer's RSA public key
 * @param {Buffer|Uint8Array} data the bytes that were signed
 * @param {Buffer|Uint8Array} signature the signature to check
 * @returns {boolean} true only for a valid signature over exactly this data
 */
function verify(publicKey, data, signature) {
  assertRsaPublicKey(publicKey);
  assertBytes(data, 'data');
  assertBytes(signature, 'signature');
  if (data.length === 0 || signature.length === 0) {
    return false; // sign() never produces these
  }
  try {
    return crypto.verify(SIGNATURE_HASH, data, pssOptions(publicKey), signature);
  } catch (err) {
    return false;
  }
}

module.exports = {
  SIGNATURE_HASH,
  PSS_SALT_LENGTH,
  sign,
  verify,
};
