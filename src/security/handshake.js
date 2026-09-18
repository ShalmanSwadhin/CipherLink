'use strict';

/**
 * Handshake message construction and verification (client side only).
 *
 *   Initiator (Client A)                         Responder (Client B)
 *   createKeyExchange()  ── KEY_EXCHANGE ──►     verifyKeyExchange()
 *   verifyKeyExchangeAck() ◄── ACK ──            createKeyExchangeAck()
 *
 * Everything cryptographic is delegated to the Phase 3 primitives
 * (generateSessionKey, rsaEncrypt/rsaDecrypt, sign/verify). The bytes that
 * are signed come from protocol/canonical.js. The server never calls this
 * module: it has no keys and does no cryptography.
 *
 * Verification order for KEY_EXCHANGE (a decrypted key is NOT trusted just
 * because decryption succeeded):
 *   1. message is well-formed and is a KEY_EXCHANGE
 *   2. sender is the expected peer
 *   3. recipient is this client
 *   4. the peer's RSA-PSS signature over the canonical handshake data
 *      (which covers version, type, sender, recipient, sessionId, the
 *      ciphertext and OUR encryption-key fingerprint) is valid
 *   5. only then: RSA-OAEP decrypt
 *   6. the result is exactly 32 bytes
 *
 * Errors are HandshakeError with fixed messages: no keys or key bytes.
 */

const {
  PROTOCOL_VERSION,
  MESSAGE_TYPES,
  validateMessage,
  createKeyExchangeMessage,
  createKeyExchangeAckMessage,
} = require('../protocol/message');
const { canonicalizeHandshake } = require('../protocol/canonical');
const { generateSessionKey, generateSessionId, SESSION_KEY_BYTES } = require('../crypto/session');
const { rsaEncrypt, rsaDecrypt } = require('../crypto/rsa');
const { sign, verify } = require('../crypto/signing');
const { publicKeyFingerprint } = require('../crypto/hash');

class HandshakeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HandshakeError';
  }
}

function requireWellFormed(message, expectedType) {
  if (!validateMessage(message).valid || message.type !== expectedType) {
    throw new HandshakeError(`Malformed ${expectedType} message.`);
  }
}

function requireParties(message, expectedSender, expectedRecipient) {
  if (message.sender !== expectedSender) {
    throw new HandshakeError('Unexpected sender.');
  }
  if (message.recipient !== expectedRecipient) {
    throw new HandshakeError('Message is not addressed to this client.');
  }
}

/**
 * Initiator: generates a fresh session key and session ID, wraps the key for
 * the peer, and signs the handshake data.
 *
 * @returns {{ message: object, sessionId: string, sessionKey: Buffer }}
 *   `message` goes on the wire; `sessionKey` must stay on this client.
 */
function createKeyExchange({ sender, recipient, signingPrivateKey, peerEncryptionPublicKey, version = PROTOCOL_VERSION }) {
  const sessionKey = generateSessionKey();
  const sessionId = generateSessionId();
  const encryptedSessionKey = rsaEncrypt(peerEncryptionPublicKey, sessionKey);

  const signedData = canonicalizeHandshake({
    version,
    type: MESSAGE_TYPES.KEY_EXCHANGE,
    sender,
    recipient,
    sessionId,
    encryptedSessionKey,
    recipientEncryptionKeyFingerprint: publicKeyFingerprint(peerEncryptionPublicKey),
  });
  const signature = sign(signingPrivateKey, signedData);

  return {
    message: createKeyExchangeMessage(
      {
        sender,
        recipient,
        sessionId,
        encryptedSessionKey: encryptedSessionKey.toString('base64'),
        signature: signature.toString('base64'),
      },
      version
    ),
    sessionId,
    sessionKey,
  };
}

/**
 * Responder: authenticates the KEY_EXCHANGE, then recovers the session key.
 *
 * @returns {{ sessionId: string, sessionKey: Buffer }}
 * @throws {HandshakeError}
 */
function verifyKeyExchange({
  message,
  expectedSender,
  expectedRecipient,
  peerSigningPublicKey,
  ownEncryptionPublicKey,
  ownEncryptionPrivateKey,
}) {
  requireWellFormed(message, MESSAGE_TYPES.KEY_EXCHANGE);
  requireParties(message, expectedSender, expectedRecipient);

  const encryptedSessionKey = Buffer.from(message.encryptedSessionKey, 'base64');
  const signedData = canonicalizeHandshake({
    version: message.version,
    type: message.type,
    sender: message.sender,
    recipient: message.recipient,
    sessionId: message.sessionId,
    encryptedSessionKey,
    recipientEncryptionKeyFingerprint: publicKeyFingerprint(ownEncryptionPublicKey),
  });
  if (!verify(peerSigningPublicKey, signedData, Buffer.from(message.signature, 'base64'))) {
    throw new HandshakeError('Invalid signature.');
  }

  let sessionKey;
  try {
    sessionKey = rsaDecrypt(ownEncryptionPrivateKey, encryptedSessionKey);
  } catch (err) {
    throw new HandshakeError('Unable to decrypt the session key.');
  }
  if (sessionKey.length !== SESSION_KEY_BYTES) {
    sessionKey.fill(0);
    throw new HandshakeError('Session key has the wrong length.');
  }

  return { sessionId: message.sessionId, sessionKey };
}

/** Responder: signed acknowledgement. Contains no key material. */
function createKeyExchangeAck({ sender, recipient, sessionId, signingPrivateKey, version = PROTOCOL_VERSION }) {
  const signedData = canonicalizeHandshake({
    version,
    type: MESSAGE_TYPES.KEY_EXCHANGE_ACK,
    sender,
    recipient,
    sessionId,
  });
  const signature = sign(signingPrivateKey, signedData);
  return createKeyExchangeAckMessage({ sender, recipient, sessionId, signature: signature.toString('base64') }, version);
}

/**
 * Initiator: authenticates the ACK for the session it started.
 * @throws {HandshakeError}
 */
function verifyKeyExchangeAck({ message, expectedSender, expectedRecipient, expectedSessionId, peerSigningPublicKey }) {
  requireWellFormed(message, MESSAGE_TYPES.KEY_EXCHANGE_ACK);
  requireParties(message, expectedSender, expectedRecipient);
  if (message.sessionId !== expectedSessionId) {
    throw new HandshakeError('Unexpected session ID.');
  }

  const signedData = canonicalizeHandshake({
    version: message.version,
    type: message.type,
    sender: message.sender,
    recipient: message.recipient,
    sessionId: message.sessionId,
  });
  if (!verify(peerSigningPublicKey, signedData, Buffer.from(message.signature, 'base64'))) {
    throw new HandshakeError('Invalid signature.');
  }
}

module.exports = {
  HandshakeError,
  createKeyExchange,
  verifyKeyExchange,
  createKeyExchangeAck,
  verifyKeyExchangeAck,
};
