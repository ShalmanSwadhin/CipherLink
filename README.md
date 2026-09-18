# CipherLink

CipherLink is a Computer Security course project building a secure TCP chat
system. The end goal is a hybrid-cryptography architecture (RSA session-key
exchange, AES-256-GCM message encryption, RSA-PSS signatures, replay
protection, session rekeying, and attack simulations), built up in
incremental, independently testable phases.

## Current phase

> **Phase 4 — Session Establishment** (public-key exchange + session-key establishment)

Phase 1 built the plain TCP relay, Phase 2 the versioned protocol with
validation, Phase 3 the cryptographic primitives (`src/crypto/`). Phase 4
uses them so that Client A and Client B can establish the **same random
AES-256 session key through the relay without the server ever seeing it**
(see [Phase 4 — Session Establishment](#phase-4--session-establishment)).

| Capability | Status |
|---|---|
| Session establishment (HELLO → KEY_EXCHANGE → KEY_EXCHANGE_ACK) | **Implemented** |
| CHAT encryption (AES-GCM) | Not implemented yet |
| Replay protection | Not implemented yet |
| Session rekeying | Not implemented yet |
| Attack simulation / benchmarking | Not implemented yet |

**Ordinary `CHAT` messages are still plaintext.** The established session
key is not used yet. To run it, jump to [Running CipherLink](#running-cipherlink).

## Architecture

```text
Client A → TCP Server → Client B
Client B → TCP Server → Client A
```

The server acts purely as a relay between two connected clients:

- It accepts TCP connections and assigns each of the first two clients an
  identity: `Client A` or `Client B`.
- A third connection attempt is rejected with an error message and closed.
- Incoming chat text from one client is relayed to the other. The server
  stamps the `sender` field itself (never trusting a client-supplied value).
- Handshake messages (`HELLO`, `KEY_EXCHANGE`, `KEY_EXCHANGE_ACK`) are
  checked for structure, connection identity and recipient, then forwarded
  **unmodified**. The server holds no keys and does no cryptography.

See [src/protocol/message.js](src/protocol/message.js) for the protocol
implementation, detailed further in [CipherLink Protocol](#cipherlink-protocol)
below.

## Requirements

- Node.js 18 or newer (developed on Node 22). Only Node's built-in modules are
  used: no external dependencies, no database, no frontend.

## Running CipherLink

You need **three terminals** in the project folder. (No `npm install` is
needed — there are no dependencies — but it is harmless.)

### Terminal 1 — start the server

```bash
npm run server
```

```text
CipherLink Server
Listening on 127.0.0.1:5000
Waiting for clients...
```

### Terminal 2 — start Client A

```bash
npm run client
```

```text
Connecting to CipherLink server at 127.0.0.1:5000...
Connected to CipherLink server
Identity: Client A
Generating identity keys...
Identity keys ready
Waiting for peer... (HELLO is sent when the other client joins)
```

The first client to connect is `Client A`. Generating its two RSA-3072 key
pairs takes about a second.

### Terminal 3 — start Client B

```bash
npm run client
```

Both terminals now show the handshake. Client A:

```text
[SYSTEM] Client B has joined the chat.
[HANDSHAKE] HELLO sent
[HANDSHAKE] HELLO received from Client B
[HANDSHAKE] Peer public keys accepted
[HANDSHAKE] Generating session key
[HANDSHAKE] KEY_EXCHANGE sent
[HANDSHAKE] KEY_EXCHANGE_ACK received from Client B
[HANDSHAKE] Signature verified
[SESSION] Established with Client B
[SESSION] ID: 32389733c3b95a07bfa8ce355a046f3d
[SESSION] Key fingerprint (diagnostic only): 3a175d34...efc9f721
[SESSION] Chat is still plaintext in this phase (message encryption is not implemented yet)
```

Client B:

```text
[SYSTEM] Client A is already connected.
[HANDSHAKE] HELLO sent
[HANDSHAKE] HELLO received from Client A
[HANDSHAKE] Peer public keys accepted
[HANDSHAKE] KEY_EXCHANGE received from Client A
[HANDSHAKE] Signature verified
[HANDSHAKE] Session key decrypted
[HANDSHAKE] KEY_EXCHANGE_ACK sent
[SESSION] Established with Client A
[SESSION] ID: 32389733c3b95a07bfa8ce355a046f3d
[SESSION] Key fingerprint (diagnostic only): 3a175d34...efc9f721
```

The order of events (the server only relays; it never sees the session key):

```text
Client A ── HELLO ─────────────────► Server ──► Client B
Client B ── HELLO ─────────────────► Server ──► Client A
Client A ── KEY_EXCHANGE ──────────► Server ──► Client B
Client B ── KEY_EXCHANGE_ACK ──────► Server ──► Client A

                 SESSION ESTABLISHED (on both clients)
```

`HELLO` is sent when the server reports that the other client is present, so
Client A prints no `HELLO sent` until Client B joins (a `HELLO` sent to an
empty room would have nobody to receive it).

**What to check:** the *Session ID* and the *Key fingerprint* are identical on
both clients (the values differ on every run). The fingerprint is a short
SHA-256 digest of the session key, printed only so you can compare; the key
itself, private keys, public-key PEMs and signatures are never printed.

Then type messages in either client and press Enter:

```text
Client A>  Hello Bob        →  Client B shows:  Client A: Hello Bob
Client B>  Hi Alice         →  Client A shows:  Client B: Hi Alice
```

**Chat is still plaintext** in this phase (see [status](#current-phase)).

### Client commands

| Command | Effect |
|---|---|
| `/status` | Show identity, peer, session state, session ID and key fingerprint |
| `/help` | List the commands |
| `/quit` | Disconnect and exit (`Ctrl+C` and `Ctrl+D` also work) |

Anything else you type is sent as a chat message; an unknown `/command` is
reported and **not** sent. Example:

```text
CipherLink Session Status

Identity: Client A
Peer: Client B (connected)
State: ESTABLISHED
Session ID: 32389733c3b95a07bfa8ce355a046f3d
Session key fingerprint: 3a175d34...efc9f721
```

### Things to try

- **Reconnect:** `/quit` Client A, then run `npm run client` again. Client B
  reports `[SESSION] Ended`; the new Client A generates fresh keys and both
  print a **new** session ID and fingerprint.
- **Third client:** start a third `npm run client` while A and B are
  connected: it is rejected (`already has two clients`) and A/B are unaffected.
- **Watch the server terminal:** it logs connections and the *type* of each
  handshake message (`HELLO`, `KEY_EXCHANGE`, `KEY_EXCHANGE_ACK`) but never
  their contents — it is a relay and never sees keys.

### Options

| Setting | Default | Notes |
|---|---|---|
| Port | `5000` | `npm run server -- 5001` / `npm run client -- 5001`, or `CIPHERLINK_PORT=5001` |
| Server bind address | `127.0.0.1` | `CIPHERLINK_HOST=0.0.0.0` to accept other machines (the chat is plaintext: only on a network you trust) |
| Client → server address | `127.0.0.1` | `CIPHERLINK_HOST=<server address>` |

Troubleshooting: `Port 5000 is already in use` means another server is
running (stop it, or use another port); `Could not connect ... Is the server
running?` means start `npm run server` first.

### Frame-size limit

Messages are newline-delimited JSON, and each message ("frame") may be at most
**64 KiB** (`MAX_FRAME_SIZE` = 65,536 UTF-8 bytes, excluding the newline).
Real messages are far smaller (a `HELLO` with two public keys is about 1.5 KB;
`KEY_EXCHANGE` about 1.4 KB). If a peer sends a longer frame, or streams data
without ever sending a newline, `LineBuffer` throws `FrameTooLargeError` after
at most one frame's worth of buffering; the server sends an `ERROR`, closes
**that** connection (the other client is told the peer left) and keeps
running. The client refuses over-long chat lines locally instead of sending
them. There is no attempt to resynchronize a stream after an oversized frame.

## CipherLink Protocol

### 1. Transport

Plain TCP (`net` module). No TLS, no encryption — that is out of scope until
a later phase.

### 2. Framing

One JSON object per line (`message\n`). TCP is a byte stream and does not
preserve message boundaries, so both sides run incoming bytes through a
`LineBuffer` that buffers partial data and splits on `\n` before anything is
parsed as JSON:

```text
Client
  │
  │ TCP byte stream
  ▼
LineBuffer
  │
  ▼
JSON decoder
  │
  ▼
Protocol validator
  │
  ▼
Message handler
  │
  ▼
Server relay
```

`LineBuffer` only knows about bytes and newlines — it has no knowledge of
message content, and cryptographic logic must never be added to it. It does
enforce a maximum frame size of 64 KiB (see [Frame-size limit](#frame-size-limit)). That
separation is what lets a future security layer wrap around the protocol
layer (encrypt/sign before `encode`, decrypt/verify after `decode`) without
touching the framing code at all.

### 3. Protocol version

Every message carries a `version` field (currently `1`, exported as
`PROTOCOL_VERSION`/`SUPPORTED_VERSIONS` from `src/protocol/message.js`). A
message with a `version` the receiver doesn't support is rejected with an
`ERROR` reply — the connection is not dropped, and the server keeps running.
For `CHAT`, `SYSTEM` and `ERROR`, a missing `version` is still accepted and
treated as version 1 (Phase 1 wire compatibility). The three handshake
types (`HELLO`, `KEY_EXCHANGE`, `KEY_EXCHANGE_ACK`) **require** `version`.
As the protocol gains encrypted/authenticated message shapes, the
version number is what lets a receiver tell which schema to expect instead
of guessing from the fields present.

### 4. Message types

| Type               | Status                | Purpose                                              |
|--------------------|------------------------|-------------------------------------------------------|
| `HELLO`            | Implemented (Phase 4)  | A client announces its two PUBLIC keys.               |
| `CHAT`             | Implemented            | Plaintext chat message, relayed by the server.        |
| `SYSTEM`           | Implemented            | Server-originated status; may carry a `PEER_JOINED` / `PEER_LEFT` event. |
| `ERROR`            | Implemented            | Server-originated rejection/error reporting.           |
| `KEY_EXCHANGE`     | Implemented (Phase 4)  | Initiator sends the RSA-OAEP-wrapped session key + signature. |
| `KEY_EXCHANGE_ACK` | Implemented (Phase 4)  | Responder's signed acknowledgement.                    |
| `REKEY`            | Reserved (vocabulary only) | Future session rekeying request.                   |
| `REKEY_ACK`        | Reserved (vocabulary only) | Future acknowledgment of a rekey.                  |

The reserved types exist as named constants and are recognized by the
validator (a message of that type gets a clear "reserved, not supported
yet" `ERROR`), but carry no schema or behavior yet.

The server accepts `CHAT`, `HELLO`, `KEY_EXCHANGE` and `KEY_EXCHANGE_ACK`
from a client. A client-sent `SYSTEM` or `ERROR` (which only the server may
originate) gets a clear `ERROR` reply.

### 5. Message schemas

```json
// HELLO (Phase 4: carries the two PUBLIC keys as SPKI PEM strings)
{
  "type": "HELLO",
  "version": 1,
  "sender": "Client A",
  "encryptionPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "signingPublicKey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

`KEY_EXCHANGE` and `KEY_EXCHANGE_ACK` are specified in
[Phase 4 — Session Establishment](#phase-4--session-establishment).

```json
// CHAT (Phase 1/2 plaintext shape)
{ "type": "CHAT", "version": 1, "sender": "Client A", "text": "Hello Bob" }
```

```json
// SYSTEM / ERROR
{ "type": "SYSTEM", "version": 1, "text": "Client B has joined the chat." }
{ "type": "ERROR",  "version": 1, "text": "CHAT message requires non-empty \"text\"." }
```

A future encrypted `CHAT` is expected to look conceptually like:

```json
{
  "type": "CHAT",
  "version": 2,
  "sessionId": "...",
  "sequence": 42,
  "timestamp": 1234567890,
  "nonce": "...",
  "ciphertext": "...",
  "authTag": "...",
  "signature": "..."
}
```

No placeholder values for those fields exist anywhere in the code yet —
they are documented, not implemented, until the key-exchange design that
will define how they're produced and checked.

### 6. Field ownership

Core protocol fields (defined and enforced today):

```text
type    - message kind
version - protocol version the sender built the message against
sender  - CHAT: the SERVER overwrites it with the connection's assigned
          identity (bookkeeping, not cryptographic).
          Handshake messages: set by the client and covered by its
          signature; the server REJECTS a mismatch but never rewrites it.
text    - client-authored application payload
```

Handshake fields (implemented in Phase 4):

```text
recipient           - client-set, signed; server checks it names the other client
sessionId           - generated by the initiating CLIENT, signed
encryptedSessionKey - generated by the initiating CLIENT (RSA-OAEP), signed
signature           - generated by the sending CLIENT (RSA-PSS), never by the server
encryptionPublicKey, signingPublicKey - the client's PUBLIC keys (HELLO)
```

Still reserved (documented only — no code generates or checks these yet):

```text
sequence   - future replay-protection counter
timestamp  - future replay-window hint
nonce      - future sender-generated, AES-GCM nonce/IV
ciphertext - future sender-generated, AES-256-GCM output (replaces text)
authTag    - future sender-generated, AES-GCM authentication tag
```

### 7. Validation

`validateMessage(msg)` in `src/protocol/message.js` performs structural
validation only (no cryptography, no authentication):

- the message must be a JSON object (not an array, string, number, or null)
- it must have a string `type`
- the type must be a known, implemented type (reserved future types and
  genuinely unknown types are both rejected, with different reasons)
- if `version` is present, it must be one CipherLink currently supports
  (required for handshake types)
- type-specific required fields must be present with the right basic type
  (e.g. `CHAT.text` must be a non-empty string)
- handshake messages have an exact field allow-list (unknown fields are
  rejected), must not contain private-key material, and their keys and
  encodings must be well-formed: `HELLO` keys must be valid RSA public keys
  of at least 3072 bits and the two keys must differ; `sessionId` is 32
  lowercase hex characters; `encryptedSessionKey` and `signature` are
  canonical base64 of an RSA-sized value

Validation is **structural**. It does not verify signatures or decrypt
anything — that happens only in the clients' security layer.

Any invalid message — malformed JSON, unknown type, missing/wrong-typed
field, or unsupported version — gets a graceful `ERROR` reply and is
otherwise dropped; it never crashes the server or the client.

## Cryptographic Foundation

Implemented with Node's built-in `crypto` module (OpenSSL) only — no custom
cryptography, no dependencies. Code lives in `src/crypto/`:

| File | Responsibility |
|---|---|
| `keys.js` | RSA key-pair generation, PEM export/import, key validation |
| `rsa.js` | RSA-OAEP encrypt/decrypt (`rsaEncrypt`, `rsaDecrypt`) |
| `signing.js` | RSA-PSS + SHA-256 `sign` / `verify` |
| `session.js` | Random 256-bit session key and 128-bit session ID (`generateSessionKey`, `generateSessionId`) |
| `hash.js` | SHA-256, public-key fingerprint, diagnostic session-key fingerprint |

### How the pieces fit together

```text
RSA is NOT used to encrypt normal chat messages.
AES will encrypt the actual chat data.
RSA is used to protect the session key.
```

```text
Client A                                          Client B
  generateSessionKey()  ── 32 random bytes
  rsaEncrypt(B.publicKey, sessionKey) ──► Server (relay only) ──► rsaDecrypt(B.privateKey, ...)
  sign(A.privateKey, protocolData)    ──► Server (relay only) ──► verify(A.publicKey, ...)
  AES-256-GCM(sessionKey, chat text)  ──► Server (relay only) ──► AES-256-GCM decrypt   [future]
```

The design goal is end-to-end encryption: private keys and session keys stay
on the clients, and the server only ever sees public keys and ciphertext.
The first two lines of this flow are implemented in Phase 4 (see below); the
AES-GCM line is not.

### RSA

Used later to establish a shared session key securely. Each client generates
its own key pair: **RSA-3072**, public exponent 65537. Keys smaller than
3072 bits (and non-RSA keys) are refused by every function in the module,
including keys imported from PEM.

- **Public key** — may be shared. Exported as SPKI PEM (`BEGIN PUBLIC KEY`).
- **Private key** — must remain on the client that generated it. Never send
  it, log it, or give it to the server. Exported as unencrypted PKCS#8 PEM
  (`BEGIN PRIVATE KEY`) solely so the owning client can store it locally;
  `*.pem`/`*.key` are git-ignored.

### RSA-OAEP

Protects the AES session key with the recipient's public key. Node
parameters: `RSA_PKCS1_OAEP_PADDING`, `oaepHash: 'sha256'` (Node applies it
to both OAEP and MGF1), empty label. OAEP is randomized, so encrypting the
same key twice gives different ciphertexts. With a 3072-bit key the largest
plaintext is 318 bytes — plenty for a 32-byte session key, and the reason
RSA cannot carry chat traffic. All decryption failures (wrong key, tampering,
bad length) raise one identical error, so failure causes are not revealed.

### AES-256

`generateSessionKey()` returns 32 bytes from `crypto.randomBytes()` (the
OS-seeded CSPRNG). **No AES encryption exists yet**; the key is only
generated. Session keys must never be logged or sent unprotected.

### RSA-PSS + SHA-256

Used later to authenticate protocol data. `sign()`/`verify()` call
`crypto.sign`/`crypto.verify` with algorithm `'sha256'`: Node hashes the data
with SHA-256 itself (no manual pre-hashing), then applies RSASSA-PSS with
`RSA_PKCS1_PSS_PADDING`, MGF1-SHA-256 and a 32-byte salt
(`RSA_PSS_SALTLEN_DIGEST`), which `verify` enforces. PSS is randomized, so the
same data yields different valid signatures. `verify` returns `false` (never
throws) for tampered data or bad/foreign signatures.

These parameters were cross-checked against the `openssl` command line
(OpenSSL decrypted Node's OAEP output and verified Node's PSS signatures;
different salt length / OAEP hash were rejected).

### Status of each primitive

"Used now" means implemented and unit-tested. Since Phase 4 the first four
are also **used by the handshake** in the clients; none of them protects
chat traffic yet.

| Primitive | Purpose | Used now? | Future use |
|---|---|---:|---|
| RSA key pair (two per client) | Public/private identity: one for encryption, one for signing | Yes (handshake) | Client identity/key operations |
| RSA-OAEP | Secure key wrapping | Yes (handshake) | Protect AES session key (also on rekey) |
| RSA-PSS + SHA-256 | Digital signatures | Yes (handshake) | Authenticate signed protocol data |
| Secure random 256-bit key | Session key | Yes (handshake) | AES-256-GCM |
| AES-256-GCM | Message encryption | No | Phase 5 |

## Phase 4 — Session Establishment

Client A and Client B agree on one random AES-256 session key **through the
relay server, without the server being able to read it, forge it or alter
it undetected**. The key is not used to encrypt anything yet.

### Handshake sequence

```text
A → Server → B : HELLO              (A's two public keys)
B → Server → A : HELLO              (B's two public keys)

A → Server → B : KEY_EXCHANGE       (session key wrapped for B, signed by A)
B → Server → A : KEY_EXCHANGE_ACK   (signed by B)

Session Established  (CHAT is still plaintext)
```

1. When the server sees both clients connected, it tells each one
   (`SYSTEM` with `event: "PEER_JOINED"`); each then sends its `HELLO`.
2. Client A always initiates, Client B always responds, so two competing
   session keys are never created.
3. A generates the 32-byte key and a random 128-bit session ID, wraps the key
   with **B's encryption public key** (RSA-OAEP), and signs the handshake
   data with **A's signing private key** (RSA-PSS + SHA-256).
4. B verifies the signature **first**, and only then decrypts and checks the
   result is exactly 32 bytes. Decryption succeeding is never treated as
   proof of anything.
5. B answers with a signed `KEY_EXCHANGE_ACK` for the same session ID; A
   verifies it. Both sides become `ESTABLISHED`.

When a peer disconnects, the server sends `PEER_LEFT` and the remaining
client discards its session state; a newly connected peer triggers a fresh
handshake with a new key and session ID.

### Messages

```json
{ "type": "KEY_EXCHANGE", "version": 1, "sender": "Client A", "recipient": "Client B",
  "sessionId": "<32 hex chars>", "encryptedSessionKey": "<base64>", "signature": "<base64>" }

{ "type": "KEY_EXCHANGE_ACK", "version": 1, "sender": "Client B", "recipient": "Client A",
  "sessionId": "<32 hex chars>", "signature": "<base64>" }
```

**What is signed.** Not `JSON.stringify` (JSON text is not canonical), but a
deterministic byte string built by `canonicalizeHandshake()` in
[src/protocol/canonical.js](src/protocol/canonical.js): each field encoded as
a 4-byte big-endian length followed by its bytes, in a fixed order, so field
boundaries are unambiguous:

```text
KEY_EXCHANGE:      label | version | type | sender | recipient | sessionId |
                   encryptedSessionKey | SHA-256(recipient's encryption public key)
KEY_EXCHANGE_ACK:  label | version | type | sender | recipient | sessionId
```

The signature therefore covers the protocol version, message type, sender,
recipient, session ID and the ciphertext. The extra recipient-key
fingerprint (not sent on the wire; the verifier computes it from its own
key) ensures a ciphertext wrapped for a different key fails verification.
Because the type is signed, a `KEY_EXCHANGE` signature cannot be reused as an
`ACK`.

### Key hierarchy

```text
Client RSA encryption key pair  ─►  RSA-OAEP (SHA-256)      ─►  protects the AES-256 session key
Client RSA signing key pair     ─►  RSA-PSS + SHA-256       ─►  authenticates the handshake
```

Each client generates **two independent RSA-3072 key pairs**; a key is never
used for both purposes, and a `HELLO` advertising the same key twice is
rejected. Only the two public keys are ever sent. Private keys never leave the
client process.

### Server role: TCP relay only

The server validates structure, checks that `sender` equals the connection's
assigned identity and that `recipient` is the other client, and forwards the
**original line byte-for-byte**. It holds no private keys, never sees the
session key, cannot decrypt the wrapped key, does not generate keys, does not
sign anything, and does not verify signatures as an authority. It logs only
the message *type* of handshake traffic.

### Session state (client side)

`src/security/peer-session.js`: `NO_SESSION → HELLO_EXCHANGED → KEY_SENT`
(initiator) or `KEY_RECEIVED` (responder) `→ ESTABLISHED`, or `FAILED` when a
handshake step fails verification. An `ESTABLISHED` session is never
overwritten: duplicate or late handshake messages are rejected and change
nothing. **This is not replay protection** (no sequence numbers or timestamps
exist yet); it only stops a repeated handshake from silently replacing a live
session.

### Diagnostic fingerprint

To let you check that both clients hold the same key without ever printing it,
each client prints a **diagnostic** fingerprint: the first and last 8 hex
characters of SHA-256(session key):

```text
[SECURITY] Session established with Client B.
           Session ID: 3f9c...
           Session key fingerprint (diagnostic only): a83f12c9...5e91c2d0
```

It is only for debugging/testing: it is not the key, not a password, and is
not used for any cryptographic purpose. Session keys and private keys are
never printed or logged.

### Public-Key Trust Limitation

CipherLink currently obtains peer public keys through the server relay.
Therefore, if the server is malicious or compromised, it could substitute a
different public key before the clients establish trust.

RSA signatures do not solve this by themselves, because the attacker could
substitute the public key used to verify the signature.

The Phase 4 protocol provides cryptographic integrity of the handshake data
**once the public keys are trusted**, but it does **not** yet protect against
a malicious server performing public-key substitution (a man-in-the-middle:
the server would replace both clients' keys with its own, complete two
handshakes and learn both session keys). The `sender` identity
(`Client A`/`Client B`) is assigned by the server and is **not**
cryptographically authenticated.

A future version could address this using mechanisms such as
certificate-based trust, pinned fingerprints, or authenticated out-of-band
key verification. None of these is implemented.

### Current status

```text
Session establishment:      implemented
AES-GCM chat encryption:    NOT YET IMPLEMENTED
Replay protection:          NOT YET IMPLEMENTED
Session rekeying:           NOT YET IMPLEMENTED
Attack benchmarking:        NOT YET IMPLEMENTED
```

Try it: start the server and two clients (see [Running](#running)). Each
client first generates its two RSA-3072 key pairs (a second or two), then the
handshake runs automatically and both print the same session ID and
fingerprint. Chat still works in plaintext.

## Testing

Seven automated test files (135 tests), no external test framework. The full suite takes roughly half a minute because it generates many RSA-3072 keys and starts real servers and clients:

```bash
npm test
```

- `tests/test-protocol.js` — unit tests for `validateMessage` and the
  message factories: valid `CHAT`/`SYSTEM`/`ERROR`/`HELLO` messages, the
  invalid cases from the Phase 2 spec (`{}`, unknown type, missing/empty/
  non-string `text`, unsupported `version`), reserved future types, and a
  sanity check that `LineBuffer` framing is untouched.
- `tests/test-handshake.js` — Phase 4 unit tests: HELLO validation (missing,
  invalid, weak, non-RSA and private keys; bad version; wrong sender),
  session-key establishment, tamper resistance (modified ciphertext, sender,
  recipient, session ID, version, foreign signer, wrong recipient, duplicate
  handshake), canonicalization, and the session state machine. No sockets.
- `tests/test-handshake-integration.js` — Phase 4 integration tests with the
  real server: raw-socket peers running the real `PeerSession` (proving the
  server never receives a session/private key and relays handshake messages
  verbatim, plus reconnect handling) and two real CLI client processes
  (matching fingerprints, plaintext chat still working).
- `tests/test-frame-limit.js` — frame-size limit: `LineBuffer` unit tests
  (exact-limit boundary, never-ending frame, oversized frame among valid ones,
  byte-accurate counting) and the real server under a 200 KB frame and a
  200 MB newline-free flood (error reply, only the offender dropped, server
  memory measured and bounded, other client and later connections unaffected).
- `tests/test-cli.js` — the real CLI: startup banner, identity/key-generation
  output, visible handshake progress, `/status` (same session ID and
  fingerprint on both clients, no secrets), `/help`, unknown commands,
  over-long messages refused locally, third-client rejection, `/quit`,
  reconnect with a new session, server-log contents, and the
  server-not-running message.
- `tests/test-crypto.js` — unit tests for the crypto primitives: key
  generation/export/import, OAEP round trip, wrong key, tampered ciphertext,
  randomization; PSS sign/verify, tampered data/signature, foreign key,
  randomization; session-key length/uniqueness; plus negative cases (weak
  and non-RSA keys, wrong key kinds, invalid input types, garbage
  ciphertext/signatures, no key material in error messages) and guards that
  the crypto sources never log and that the server stays crypto-free.
- `tests/test-server.js` — integration tests that drive the real server
  over raw TCP sockets: startup, both clients connecting and being assigned
  identities, bidirectional relay, rapid-fire messages, message framing
  (split TCP chunks and multiple messages per chunk), malformed JSON and
  empty-message handling, client disconnect stability, slot reuse after a
  disconnect, graceful rejection of a third client, and — new in Phase 2 —
  rejection of structurally invalid protocol messages, of a structurally
  valid but unaccepted type (`SYSTEM`), and of reserved future types,
  confirming in each case that the server keeps relaying normally
  afterwards.
