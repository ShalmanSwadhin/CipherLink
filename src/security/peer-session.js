'use strict';

/**
 * Client-side session state for the (single) peer: a small state machine
 * that drives HELLO -> KEY_EXCHANGE -> KEY_EXCHANGE_ACK.
 *
 *   NO_SESSION -> HELLO_EXCHANGED -> KEY_SENT     -> ESTABLISHED   (Client A, initiator)
 *   NO_SESSION -> HELLO_EXCHANGED -> KEY_RECEIVED -> ESTABLISHED   (Client B, responder)
 *                          any handshake step that fails verification -> FAILED
 *
 * Client A always initiates and Client B always responds, so the two
 * clients never create competing session keys.
 *
 * This class does no networking: feed it received messages and send what
 * it returns in `outgoing`. It only holds state for THIS client; the
 * server never sees any of it.
 *
 * Rules worth knowing:
 *   - A session key is only exposed once the state is ESTABLISHED.
 *   - An ESTABLISHED session is never overwritten: duplicate/late
 *     HELLO, KEY_EXCHANGE or ACK messages are rejected and change nothing.
 *     (This is NOT replay protection - no sequence numbers or timestamps
 *     exist yet - it only stops a repeated handshake from silently
 *     replacing a live session.)
 *   - A session ends only via onPeerLeft() (server presence notice).
 */

const { MESSAGE_TYPES, validateMessage, createHelloMessage } = require('../protocol/message');
const { importPublicKey } = require('../crypto/keys');
const { sessionKeyFingerprint } = require('../crypto/hash');
const { exportPublicKeys } = require('./identity');
const {
  HandshakeError,
  createKeyExchange,
  verifyKeyExchange,
  createKeyExchangeAck,
  verifyKeyExchangeAck,
} = require('./handshake');

const SESSION_STATES = Object.freeze({
  NO_SESSION: 'NO_SESSION',
  HELLO_EXCHANGED: 'HELLO_EXCHANGED',
  KEY_SENT: 'KEY_SENT',
  KEY_RECEIVED: 'KEY_RECEIVED',
  ESTABLISHED: 'ESTABLISHED',
  FAILED: 'FAILED',
});

const INITIATOR_ID = 'Client A';
const PEER_OF = Object.freeze({ 'Client A': 'Client B', 'Client B': 'Client A' });

class PeerSession {
  #identity;
  #state;
  #helloSent;
  #sessionId;
  #sessionKey;
  #peerEncryptionPublicKey;
  #peerSigningPublicKey;

  /**
   * @param {object} options
   * @param {string} options.selfId this client's server-assigned identity
   * @param {object} options.identity result of createIdentity()
   */
  constructor({ selfId, identity }) {
    if (!PEER_OF[selfId]) {
      throw new TypeError('selfId must be "Client A" or "Client B".');
    }
    this.selfId = selfId;
    this.peerId = PEER_OF[selfId];
    this.#identity = identity;
    this.#reset();
  }

  get state() {
    return this.#state;
  }

  get sessionId() {
    return this.#sessionId;
  }

  get peerEncryptionPublicKey() {
    return this.#peerEncryptionPublicKey;
  }

  get peerSigningPublicKey() {
    return this.#peerSigningPublicKey;
  }

  /** The AES-256 session key, only once ESTABLISHED (for the future encryption layer). Never log it. */
  get sessionKey() {
    return this.#state === SESSION_STATES.ESTABLISHED ? this.#sessionKey : null;
  }

  /** Diagnostic-only short SHA-256 fingerprint of the session key, or null if not established. */
  sessionKeyFingerprint() {
    return this.sessionKey ? sessionKeyFingerprint(this.sessionKey) : null;
  }

  #reset() {
    if (this.#sessionKey) this.#sessionKey.fill(0);
    this.#state = SESSION_STATES.NO_SESSION;
    this.#helloSent = false;
    this.#sessionId = null;
    this.#sessionKey = null;
    this.#peerEncryptionPublicKey = null;
    this.#peerSigningPublicKey = null;
  }

  #ownHelloOnce() {
    if (this.#helloSent) return [];
    this.#helloSent = true;
    const { encryptionPublicKey, signingPublicKey } = exportPublicKeys(this.#identity);
    return [createHelloMessage(this.selfId, encryptionPublicKey, signingPublicKey)];
  }

  #result(outgoing, event, error) {
    return { outgoing, event: event || null, error: error || null };
  }

  #reject(reason) {
    return this.#result([], null, reason);
  }

  #fail(err) {
    if (this.#sessionKey) this.#sessionKey.fill(0);
    this.#sessionKey = null;
    this.#state = SESSION_STATES.FAILED;
    // Only our own fixed HandshakeError texts are surfaced.
    return this.#reject(err instanceof HandshakeError ? err.message : 'Handshake failed.');
  }

  /** The server reported the peer is present: send our HELLO (once). */
  onPeerJoined() {
    return this.#result(this.#ownHelloOnce(), null, null);
  }

  /** The server reported the peer left: forget everything about the session. */
  onPeerLeft() {
    this.#reset();
  }

  /**
   * @param {object} msg a decoded HELLO, KEY_EXCHANGE or KEY_EXCHANGE_ACK
   * @returns {{ outgoing: object[], event: string|null, error: string|null }}
   *   event is one of PEER_KEYS_RECEIVED, KEY_EXCHANGE_SENT, ESTABLISHED
   */
  handleMessage(msg) {
    const validation = validateMessage(msg);
    if (!validation.valid) {
      return this.#reject(validation.reason);
    }
    switch (msg.type) {
      case MESSAGE_TYPES.HELLO:
        return this.#onHello(msg);
      case MESSAGE_TYPES.KEY_EXCHANGE:
        return this.#onKeyExchange(msg);
      case MESSAGE_TYPES.KEY_EXCHANGE_ACK:
        return this.#onKeyExchangeAck(msg);
      default:
        return this.#reject(`Unexpected ${msg.type} message during the handshake.`);
    }
  }

  #onHello(msg) {
    if (msg.sender !== this.peerId) {
      return this.#reject('HELLO sender is not the expected peer.');
    }
    if (this.#state !== SESSION_STATES.NO_SESSION) {
      return this.#reject('Unexpected HELLO: a handshake is already in progress or established.');
    }

    this.#peerEncryptionPublicKey = importPublicKey(msg.encryptionPublicKey);
    this.#peerSigningPublicKey = importPublicKey(msg.signingPublicKey);
    this.#state = SESSION_STATES.HELLO_EXCHANGED;

    // Our HELLO must precede any KEY_EXCHANGE we send, or the peer has no key to verify with.
    const outgoing = this.#ownHelloOnce();
    if (this.selfId !== INITIATOR_ID) {
      return this.#result(outgoing, 'PEER_KEYS_RECEIVED', null);
    }

    try {
      const exchange = createKeyExchange({
        sender: this.selfId,
        recipient: this.peerId,
        signingPrivateKey: this.#identity.signing.privateKey,
        peerEncryptionPublicKey: this.#peerEncryptionPublicKey,
      });
      this.#sessionId = exchange.sessionId;
      this.#sessionKey = exchange.sessionKey;
      this.#state = SESSION_STATES.KEY_SENT;
      outgoing.push(exchange.message);
      return this.#result(outgoing, 'KEY_EXCHANGE_SENT', null);
    } catch (err) {
      return this.#fail(err);
    }
  }

  #onKeyExchange(msg) {
    if (this.selfId === INITIATOR_ID) {
      return this.#reject('Only the responder accepts KEY_EXCHANGE.');
    }
    if (this.#state === SESSION_STATES.ESTABLISHED) {
      return this.#reject('Session already established; duplicate KEY_EXCHANGE ignored.');
    }
    if (this.#state !== SESSION_STATES.HELLO_EXCHANGED) {
      return this.#reject(`KEY_EXCHANGE is not acceptable in state ${this.#state}.`);
    }

    this.#state = SESSION_STATES.KEY_RECEIVED;
    try {
      const { sessionId, sessionKey } = verifyKeyExchange({
        message: msg,
        expectedSender: this.peerId,
        expectedRecipient: this.selfId,
        peerSigningPublicKey: this.#peerSigningPublicKey,
        ownEncryptionPublicKey: this.#identity.encryption.publicKey,
        ownEncryptionPrivateKey: this.#identity.encryption.privateKey,
      });
      const ack = createKeyExchangeAck({
        sender: this.selfId,
        recipient: this.peerId,
        sessionId,
        signingPrivateKey: this.#identity.signing.privateKey,
      });
      this.#sessionId = sessionId;
      this.#sessionKey = sessionKey;
      this.#state = SESSION_STATES.ESTABLISHED;
      return this.#result([ack], 'ESTABLISHED', null);
    } catch (err) {
      return this.#fail(err);
    }
  }

  #onKeyExchangeAck(msg) {
    if (this.selfId !== INITIATOR_ID) {
      return this.#reject('Only the initiator accepts KEY_EXCHANGE_ACK.');
    }
    if (this.#state === SESSION_STATES.ESTABLISHED) {
      return this.#reject('Session already established; duplicate KEY_EXCHANGE_ACK ignored.');
    }
    if (this.#state !== SESSION_STATES.KEY_SENT) {
      return this.#reject(`KEY_EXCHANGE_ACK is not acceptable in state ${this.#state}.`);
    }

    try {
      verifyKeyExchangeAck({
        message: msg,
        expectedSender: this.peerId,
        expectedRecipient: this.selfId,
        expectedSessionId: this.#sessionId,
        peerSigningPublicKey: this.#peerSigningPublicKey,
      });
    } catch (err) {
      return this.#fail(err);
    }
    this.#state = SESSION_STATES.ESTABLISHED;
    return this.#result([], 'ESTABLISHED', null);
  }
}

module.exports = {
  SESSION_STATES,
  INITIATOR_ID,
  PeerSession,
};
