'use strict';

/**
 * RSA key-pair generation, PEM serialization and key validation.
 *
 * Public key  - may be shared freely (it is what peers use to encrypt to
 *               you and to verify your signatures).
 * Private key - must NEVER leave the client that generated it: not sent
 *               over the network, not given to the server, not logged.
 *
 * Keys are handled as Node.js `KeyObject`s. Node keeps the key material
 * inside OpenSSL; a KeyObject is not printable, so logging one by accident
 * does not reveal the key. Only exportPrivateKey() turns it into text.
 *
 * Parameters:
 *   - RSA, 3072-bit modulus (~128-bit security level), public exponent 65537.
 *   - Anything below MIN_MODULUS_LENGTH is refused everywhere in this
 *     module family, including keys imported from PEM or created elsewhere.
 */

const crypto = require('crypto');

const RSA_MODULUS_LENGTH = 3072;
const RSA_PUBLIC_EXPONENT = 0x10001; // 65537
const MIN_MODULUS_LENGTH = 3072;

/**
 * Generates a fresh RSA key pair. Synchronous: 3072-bit generation takes
 * a noticeable fraction of a second to a few seconds, which is acceptable
 * once per client at startup.
 *
 * @returns {{ publicKey: crypto.KeyObject, privateKey: crypto.KeyObject }}
 */
function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: RSA_MODULUS_LENGTH,
    publicExponent: RSA_PUBLIC_EXPONENT,
  });
}

/**
 * Shared guard used by every crypto function that accepts a key: it must
 * be an RSA KeyObject of the expected type and meet the minimum size.
 * Throws TypeError/RangeError with a fixed message that never includes key
 * material.
 */
function assertRsaKey(key, type) {
  if (!(key instanceof crypto.KeyObject) || key.type !== type) {
    throw new TypeError(`Expected an RSA ${type} key (crypto.KeyObject).`);
  }
  if (key.asymmetricKeyType !== 'rsa') {
    throw new TypeError(`Expected an RSA ${type} key, got a different key type.`);
  }
  if (key.asymmetricKeyDetails.modulusLength < MIN_MODULUS_LENGTH) {
    throw new RangeError(`RSA key is too small; at least ${MIN_MODULUS_LENGTH} bits are required.`);
  }
}

function assertRsaPublicKey(key) {
  assertRsaKey(key, 'public');
}

function assertRsaPrivateKey(key) {
  assertRsaKey(key, 'private');
}

/** Exports a public key as an SPKI PEM string ("-----BEGIN PUBLIC KEY-----"). Safe to share. */
function exportPublicKey(publicKey) {
  assertRsaPublicKey(publicKey);
  return publicKey.export({ type: 'spki', format: 'pem' });
}

/**
 * Exports a private key as an UNENCRYPTED PKCS#8 PEM string
 * ("-----BEGIN PRIVATE KEY-----"). Intended only for writing to the
 * owning client's own local storage. Never send, share or log the result.
 */
function exportPrivateKey(privateKey) {
  assertRsaPrivateKey(privateKey);
  return privateKey.export({ type: 'pkcs8', format: 'pem' });
}

/** Imports an SPKI PEM public key. Rejects private-key PEMs, non-RSA keys and weak keys. */
function importPublicKey(pem) {
  if (typeof pem !== 'string' || !pem.includes('-----BEGIN PUBLIC KEY-----')) {
    throw new TypeError('Expected a PEM string containing an SPKI public key.');
  }
  let key;
  try {
    key = crypto.createPublicKey({ key: pem, format: 'pem' });
  } catch (err) {
    // Fixed message: OpenSSL's own message is not forwarded.
    throw new Error('Invalid public key PEM.');
  }
  assertRsaPublicKey(key);
  return key;
}

/** Imports an unencrypted PKCS#8 PEM private key. Rejects public-key PEMs, non-RSA keys and weak keys. */
function importPrivateKey(pem) {
  if (typeof pem !== 'string' || !pem.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new TypeError('Expected a PEM string containing a PKCS#8 private key.');
  }
  let key;
  try {
    key = crypto.createPrivateKey({ key: pem, format: 'pem' });
  } catch (err) {
    // Fixed message: never echo the PEM or the underlying parser error.
    throw new Error('Invalid private key PEM.');
  }
  assertRsaPrivateKey(key);
  return key;
}

module.exports = {
  RSA_MODULUS_LENGTH,
  RSA_PUBLIC_EXPONENT,
  MIN_MODULUS_LENGTH,
  generateKeyPair,
  assertRsaPublicKey,
  assertRsaPrivateKey,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
};
