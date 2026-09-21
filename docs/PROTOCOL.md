# ECP v3 protocol review notes

These notes describe the experimental implementation in `src/ratchet.ts`, `src/codec.ts`, `src/crypto.ts` and `src/identity.ts`. They are a review aid, not a standardized protocol, proof of security, independent audit or promise of interoperability. Any discrepancy must be resolved against the source and tests. The unresolved assurance requirements in `SECURITY.md` remain applicable.

## Encoding and versions

An envelope is `e2e3:` followed by canonical unpadded base64url. The decoded envelope is at most 1,048,576 bytes. The UI accepts up to eight concatenated packets within that overall bound. A public identity bundle is also transported in an envelope but has no packet header.

All packets have a 12-byte outer header. Multi-byte integers use unsigned big-endian encoding. Offsets below are zero-based and end-exclusive.

| Offset | Length | Meaning                                        |
| ------ | -----: | ---------------------------------------------- |
| 0      |      4 | ASCII `E2E3`                                   |
| 4      |      1 | Wire version `3`                               |
| 5      |      1 | Type: INIT=1, RESP=2, MSG=3                    |
| 6      |      2 | Reserved, must be zero                         |
| 8      |      4 | Payload length, exactly packet length minus 12 |

The parser rejects unsupported magic/version/type, nonzero reserved fields, noncanonical encoding, oversize input, trailing data and incomplete packets. There is no downgrade negotiation. Stored sessions must also identify wire version 3. A v2 session requires explicit reset; upgrading never rewrites its version to make it eligible for sending.

An identity bundle remains 4,225 bytes: identity version 1 (1 byte), Ed25519 public key (32), ML-DSA-87 public key (2,592), X25519 public key (32), ML-KEM-1024 public key (1,568). Its fingerprint remains base64url(SHA-256(`ECP-ID-v2` || the four public keys)). This domain is intentionally unchanged: the wire upgrade preserves existing identity fingerprints. Peers must compare the full fingerprint through a separate trusted channel.

## Authenticated encryption

Wire keys are 32 bytes. Every encryption calls `encryptPacket`, which obtains a fresh 12-byte nonce using the platform cryptographic RNG and returns `nonce || ciphertext || tag`. AES-256-GCM-SIV produces a 16-byte tag; packet overhead is therefore 28 bytes, even for empty plaintext. Decryption authenticates before plaintext is returned. RNG failures abort; callers cannot select a wire nonce.

AES-GCM-SIV is described by [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html). Its nonce misuse resistance limits damage if a key/nonce pair accidentally repeats; the RFC still recommends random nonces. It does not provide snapshot freshness, malicious endpoint protection, anonymity or protocol composition assurance. The test suite includes four AES-256 known-answer vectors from Appendix C.2 rather than relying only on encrypt/decrypt round trips.

The vault is a separate layer: it retains Web Crypto AES-256-GCM with a fresh random IV on each record write and the unchanged encrypted-vault schema. Wire AEAD changes do not silently migrate or replace vault encryption.

## Derivation notation

`H` means SHA-256, `HMAC` means HMAC-SHA-256, and `HKDF(ikm, salt, info, size)` means HKDF-SHA-256. Labels are exact UTF-8 bytes with no terminator. `Z32` is 32 zero bytes. Concatenation is `||`.

| Purpose                                         | Derivation                                 |
| ----------------------------------------------- | ------------------------------------------ |
| Initial shared secret `SK`                      | `HKDF("ECP-INIT-v3"                        |     | dh                                                                              |     | kem, Z32, "", 32)`     |
| Initial root `RK0`                              | `HKDF(SK, Z32, "ECP-DR-ROOT-v3", 32)`      |
| INIT message material                           | `HKDF(SK, Z32, "ECP-INIT-MESSAGE-v3", 32)` |
| INIT or MSG AEAD key from message material `mk` | `HKDF(mk, Z32, "ECP-AES256GCMSIV-v3", 32)` |
| RESP AEAD key                                   | `HKDF(SK, Z32, "ECP-RESP-v3", 32)`         |
| Ratchet root/chain output                       | `HKDF(dh                                   |     | kem, RK, "ECP-DR-RK-v3", 64)`; first 32 bytes become root, last 32 become chain |
| Message material from chain `CK`                | `HMAC(CK, 0x01)`                           |
| Next chain                                      | `HMAC(CK, 0x02)`                           |
| Conversation ID                                 | First 16 bytes of `H("ECP-CONVERSATION-v3" |     | initiatorEphemeralX25519Public                                                  |     | initialKemCiphertext)` |
| INIT replay identifier                          | `H("ECP-INIT-REPLAY-v3"                    |     | signedTranscript)`                                                              |

The initial DH combines the initiator's ephemeral X25519 key with the recipient's static X25519 key. Initial KEM encapsulation targets the recipient's static ML-KEM public key. This initial secret does not, on its own, establish forward secrecy against later compromise of recipient static private keys. INIT deliberately carries no user content.

## INIT

INIT is exactly 14,781 bytes.

| Offset | Length | Meaning                                                        |
| ------ | -----: | -------------------------------------------------------------- |
| 0      |     12 | Outer header                                                   |
| 12     |  4,225 | Sender identity bundle                                         |
| 4,237  |  4,225 | Recipient identity bundle                                      |
| 8,462  |     32 | Initiator ephemeral X25519 public key                          |
| 8,494  |  1,568 | Initial ML-KEM ciphertext                                      |
| 10,062 |  4,691 | Ed25519 signature (64) followed by ML-DSA-87 signature (4,627) |
| 14,753 |     12 | Fresh AEAD nonce                                               |
| 14,765 |     16 | Authentication tag for empty plaintext                         |

The signed transcript is `"ECP-INIT-v3" || senderBundle || recipientBundle || ephemeralPublic || kemCiphertext`. Both signatures must verify. The AEAD associated data is the complete outer header and fixed public fields through the signature (`packet[0:14753]`). There is no application plaintext.

CreateInit persists a `HANDSHAKE_SENT` session before returning its packet. ProcessInit verifies the exact local destination, independently verified sender bundle, signatures, empty authenticated content, absence of an existing channel and absence of a durable transcript replay identifier. It then commits the replay record and new session together. A different randomized signature over the same transcript does not bypass replay tracking.

## RESP

RESP is exactly 3,208 bytes: outer header (12), fresh nonce (12), encrypted response (3,168), tag (16). The encrypted response is responder X25519 public key (32) || ML-KEM encapsulation ciphertext targeting the initiator's static KEM public key (1,568) || responder's new ML-KEM public key (1,568). The outer header is the associated data.

The responder derives root and sending-chain material from a fresh X25519 key paired with the initiator's ephemeral key and the KEM shared secret, salted with RK0. The initiator derives the matching receiving chain after authenticating the response with its pending SK. It deletes its pending SK from the persisted session, stores the exact accepted response hash, and enters `ESTABLISHED`. The responder has an established sending chain after accepting INIT. Both paths return ciphertext/state only after the corresponding transaction commits.

Only an exact previously accepted RESP digest for a current verified established session is treated as a duplicate. Unrelated established sessions do not make an arbitrary response acceptable. A responder may bundle its cached RESP before a MSG to tolerate a lost initial response.

## MSG and ratchet state

A MSG is at least 3,232 bytes, with a maximum UTF-8 plaintext length of 1,045,344 bytes.

| Offset       |   Length | Meaning                                |
| ------------ | -------: | -------------------------------------- |
| 0            |       12 | Outer header                           |
| 12           |       16 | Conversation ID                        |
| 28           |       32 | Sender ratchet X25519 public key       |
| 60           |    1,568 | Ratchet KEM ciphertext                 |
| 1,628        |    1,568 | Sender ratchet ML-KEM public key       |
| 3,196        |        4 | Previous sending-chain length PN       |
| 3,200        |        4 | Current sending-chain message number N |
| 3,204        |       12 | Fresh AEAD nonce                       |
| 3,216        | Variable | UTF-8 plaintext ciphertext             |
| End minus 16 |       16 | Authentication tag                     |

Associated data is `"ECP-MSG-v3" || conversationId || senderIdentityBundle || recipientIdentityBundle || packet[12:3204]`. The outer MSG header is validated separately with fixed magic/version/type/reserved fields and exact total length. The identity order is identical at both endpoints.

Sending derives a message key and next chain key from the current CKs and commits the incremented Ns and outgoing history atomically. When no sending chain exists, it generates fresh DH and KEM ratchet keys, encapsulates to the current peer KEM key, derives a new root/chain, records PN and resets Ns to zero.

Receiving looks up the conversation, requires an established v3 session and unchanged verified peer identity, then authenticates using a cached skipped key or the appropriate receiving chain. For a changed DH public key, it first derives bounded skipped keys for the previous chain, derives the new receiving root/chain, updates peer ratchet keys and creates the next local sending chain. The new receiving chain is assigned after that transition so it is not overwritten by an older staged value. State mutations remain operation-local until authentication and transaction success.

The combined previous/new-chain skipped-position budget is 100 per packet, validated before skip loops or DH/KEM work. The cache retains at most 100 skipped keys. A cached key is removed only on successful authentication and commit. Negative gaps, already consumed positions and exhausted unsigned 32-bit counters are rejected. Malformed UTF-8 is rejected after authentication without committing state.

## Persistence, operation lifetime and recovery

Each public protocol operation captures a vault-access guard before joining the origin-wide state Web Lock. The guard is checked upon acquiring the lock and before/after each asynchronous operation. A lock/unlock cycle invalidates the guard even if the vault is unlocked again before the queued action resumes. Identity creation has its own origin-wide lock with the same lifetime guard. Storage encrypts batches before committing in one IndexedDB transaction, with vault/metadata checks and transaction completion awaited.

Peer deletion/reset uses the state lock and removes all histories indexed by that peer. INIT replay tombstones survive these operations. Whole-vault deletion removes identity and replay data. Neither logical deletion nor locking promises physical memory/storage erasure.

Restoring an old valid database restores ratchet keys, counters and replay history. Fresh packet nonces prevent deterministic key/nonce reuse when randomness remains healthy; GCM-SIV further reduces the effect of accidental reuse. Nevertheless, a restored receiver can accept an old packet again, forked peers can diverge, and a live receiver rejects a second branch at an already consumed chain position. Session cloning and snapshot restoration are unsupported. Retire restored identities and reverify new channels after a profile restore.

## Evidence still required

Independent reviewers should assess hybrid-secret composition, identity and transcript binding, key confirmation, state-machine edge cases, simultaneous and out-of-order traffic, malicious authenticated peers, downgrade handling, restore/fork behavior, engine side channels and the executable release supply chain. There is no external audit report or formal security proof for this application. Passing RFC vectors validates selected primitive computations, not the complete protocol.
