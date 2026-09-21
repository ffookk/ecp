# Security policy and review scope

## Status

ECP Hardened is an experimental fork of [jamesliu96/ecp](https://github.com/jamesliu96/ecp). Its custom v2 protocol and the integration of its cryptographic components have **not received an independent security audit or formal verification**. Regression tests provide evidence for specific behaviors; they do not establish suitability for high-risk communications.

Only the current v2 implementation is within this fork's active review scope. v1 wire packets are incompatible, and legacy plaintext storage is not automatically migrated. There is no promised security support period, response deadline, incident-response service, or automatic deployment channel.

## Assets and trust boundaries

The principal assets are identity private keys, ratchet and skipped-message keys, passphrases, decrypted messages/media, peer identity verification, and the integrity of local protocol state.

Relevant entry points include public identity bundles, manually imported clipboard envelopes, authenticated but potentially malicious peer messages, media data URLs, browser storage, concurrently open tabs, and build/deployment inputs.

The application assumes:

- The executed application code, cryptographic dependencies, browser and operating system are trusted.
- Peers compare full fingerprints through an independently trusted channel before accepting each other's public bundles.
- Users select strong vault passphrases and understand that browser storage is local to an origin and profile.
- Protocol operations can use Web Locks, Web Crypto and IndexedDB in a secure context.

A packet-delivery service may observe, modify, replay, omit or reorder packets. A peer may be malicious even after its fingerprint is correctly verified. These inputs must not be trusted merely because they have valid framing or an authenticated sender.

## Intended protections to review

These are implementation objectives and testable invariants, not an assertion that every attack has been excluded:

1. Unknown or unverified public identities cannot bootstrap a channel. INIT binds the exact sender and recipient bundles and carries no user message. An existing channel cannot be silently replaced.
2. Every sending-chain position is consumed at most once within the current, non-restored session state. Origin-wide locking covers the complete read/modify/commit operation, including concurrent sends and receives from separate tabs. Ciphertext is returned only after the corresponding write batch has completed.
3. Authentication failures, malformed input and transaction aborts do not advance stored ratchet state or create history. State and history changes commit atomically.
4. Replay identifiers derive from authenticated INIT transcripts and remain after channel or peer deletion. Only an exact accepted RESP can be treated as an established-handshake duplicate.
5. Framing, decoded size, counters, and the combined previous/new-chain skip budget are bounded before expensive skip or ratchet operations. Skipped-key retention is bounded.
6. Vault records are encrypted and authenticated with fresh random IVs, store/index/vault binding, and strict metadata validation. Corruption or a wrong passphrase must not silently reset a vault or overwrite it with a new identity.
7. Locking invalidates pending operations. Operations completing after a lock must not publish decrypted data, restore a key, or commit stale state. Peer deletion removes all histories indexed by that peer, not only the most recent conversation.
8. Untrusted text and aliases are rendered as text; media sources, page execution and network capabilities remain constrained. Security checks must not rely exclusively on UI validation.

For code review, trace these boundaries across `src/main.ts`, `src/identity.ts`, `src/codec.ts`, `src/ratchet.ts`, `src/storage.ts`, `src/locks.ts`, and the emitted browser code. Include build scripts, vendored dependency provenance, browser behavior and deployment configuration when they affect a demonstrated path. Repository prose is not proof that a control is implemented.

## Vault protection and exposed metadata

The vault derives a non-extractable Web Crypto AES-256-GCM key from the passphrase using PBKDF2-HMAC-SHA-256, 600,000 iterations and a random 16-byte salt. Each write uses a fresh random 12-byte IV. The passphrase is not intentionally stored by the application. A non-extractable key prevents ordinary API key export; it does not stop malicious code in an unlocked page from using the key or reading plaintext.

Record payloads encrypt private keys, public bundles, aliases, timestamps, message/media contents, ratchet state and replay-owner associations. Necessary query identifiers remain in cleartext: contact fingerprints, conversation IDs, message IDs and replay hashes. Record counts, ciphertext sizes, store layout, IVs, salt, iteration count and vault identifier are also exposed. Someone holding a database copy can attempt offline password guesses.

The automatic lock is scheduled after five minutes of observed inactivity, with a manual lock control and `pagehide` handling. Browser scheduling can delay timers. BroadcastChannel distributes lock requests to other tabs when supported. Buffer clearing and dropping key references are best effort: JavaScript garbage collection, immutable strings, browser internals, operating-system memory management and extensions prevent a guarantee of memory erasure.

## Limits and non-goals

- **No blanket cryptographic assurance.** X25519, ML-KEM-1024, Ed25519, ML-DSA-87, HKDF/HMAC-SHA-256 and AES-256-GCM are components of a custom composition here. Do not claim proven forward secrecy, post-compromise recovery, quantum security or non-repudiation for this application. Retained local plaintext history remains readable to someone who can unlock the vault.
- **No protection from compromised endpoints or delivered code.** Malware, malicious extensions, modified first-party scripts, debugging access and hostile hosting can capture passphrases, plaintext or keys. CSP and a non-extractable vault key do not remove this trust boundary.
- **No anonymity or metadata-hiding transport.** Public identity bundles, conversation IDs, counters, ratchet public parameters, timing, recipient routing and packet sizes can be observed. The host also sees ordinary requests when the app is served remotely.
- **No clipboard or recipient erasure.** Clipboard history/synchronization, other applications, screenshots, recipient copies and external transports are outside vault control.
- **No secure deletion guarantee.** Database deletion is logical deletion. It cannot guarantee erasure from browser/OS backups, filesystem snapshots, storage media or previously copied data. Legacy `ECP_DB` records remain until the user explicitly deletes them on the relevant origin/profile.
- **Replay records deliberately persist.** Peer deletion and channel reset retain replay records. Destroying the entire vault removes them with the identity. They can grow over time and have no automatic expiry policy.
- **No rollback-resistant storage or session cloning.** At-rest AEAD detects tampering with authenticated records; it cannot prove the freshness of an entire valid database snapshot. There is no trusted external monotonic counter. Restoring old state or simultaneously using cloned profiles can repeat sending-chain state and therefore reuse an encryption key and nonce, as well as restore old replay history. Do not clone or restore active session databases. After a profile restore, retire the restored identity and establish fresh identities and independently verified channels. Browser-profile copying is not a supported backup or migration workflow.
- **No backup or recovery feature.** There is no supported key backup, vault export/import, passphrase reset/change or account recovery. Storage loss or a forgotten passphrase can be permanent.
- **No availability or delivery guarantee.** Users move packets manually. Lost packets, exhausted skip budgets, locked storage, browser quotas or unavailable clipboard permissions can interrupt communication. Local history is not proof of remote receipt.
- **No engine-side-channel guarantee.** The application does not establish constant-time execution, secure memory isolation or side-channel resistance across JavaScript engines and devices.

These boundaries must not be used to dismiss an in-scope bug that lets an untrusted packet obtain the same privileges, an incorrect deletion/lock behavior, or an application-controlled leak of sensitive data.

## Reporting a vulnerability

Report fork-specific issues to the maintainers of the repository containing this file. If that repository has GitHub private vulnerability reporting enabled, use its **Security → Report a vulnerability** flow. If no private reporting channel is available, open a minimal issue asking for one before sharing exploit details that could expose users. Do not assume that the upstream maintainer operates or endorses this fork.

Include the affected commit, browser/OS and Node versions when relevant, an isolated reproduction using synthetic identities and messages, the attacker prerequisites, expected versus observed behavior, and the specific source-to-impact path. Distinguish a reproduced result from a static candidate or design question. Do not attach real passphrases, private keys, browser profiles, personal message history or third-party data.

Do not test other users, the upstream deployment or a public hosted instance without separate authorization. Use isolated local profiles and synthetic data. There is no bug bounty or response-time commitment stated by this project.
