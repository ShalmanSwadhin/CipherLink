'use strict';

/**
 * A client's long-lived key material: TWO independent RSA key pairs.
 *
 *   encryption - RSA-OAEP: peers wrap the AES session key for us with the
 *                public half; only we can unwrap it with the private half.
 *   signing    - RSA-PSS + SHA-256: we sign handshake data with the private
 *                half; peers verify with the public half.
 *
 * Separate pairs keep the two purposes cryptographically independent (one
 * key never signs and decrypts). The private keys never leave the client:
 * they are not part of any message and are never exported by this module.
 */

const { generateKeyPair, exportPublicKey } = require('../crypto/keys');

/**
 * @returns {{ encryption: {publicKey, privateKey}, signing: {publicKey, privateKey} }}
 */
function createIdentity() {
  return Object.freeze({
    encryption: generateKeyPair(),
    signing: generateKeyPair(),
  });
}

/** PEM strings of the two PUBLIC keys - the only key material that is ever sent. */
function exportPublicKeys(identity) {
  return {
    encryptionPublicKey: exportPublicKey(identity.encryption.publicKey),
    signingPublicKey: exportPublicKey(identity.signing.publicKey),
  };
}

module.exports = {
  createIdentity,
  exportPublicKeys,
};
