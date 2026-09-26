# Security policy and review scope

## Status

ECP Hardened is an experimental fork of [jamesliu96/ecp](https://github.com/jamesliu96/ecp). Its custom v3 protocol and the integration of its cryptographic components have **not received an independent security audit or formal verification**. Regression tests provide evidence for specific behaviors; they do not establish suitability for high-risk communications.

Only the current v3 wire implementation and retained v2 encrypted-vault schema are within this fork's active review scope. v1 and v2 wire packets are incompatible, and legacy plaintext storage is not automatically migrated. There is no promised security support period, response deadline, incident-response service, or automatic deployment channel.

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
7. Locking invalidates pending operations, including work already queued on an origin or identity lock before a later unlock. Operations completing after a lock must not publish decrypted data, restore a key, or commit stale state. Peer deletion removes all histories indexed by that peer, not only the most recent conversation. Queued peer deletion and channel wipe revalidate their confirmation context after obtaining the state lock and immediately before mutation; canceling or changing context before that point must preserve data.
8. Each wire encryption generates its nonce inside the common authenticated-encryption wrapper. Old wire versions cannot be silently upgraded or accepted; old stored sessions require an explicit channel reset.
9. Untrusted text and aliases are rendered as text; media sources, page execution and network capabilities remain constrained. Security checks must not rely exclusively on UI validation.

For code review, trace these boundaries across `src/main.ts`, `src/identity.ts`, `src/codec.ts`, `src/ratchet.ts`, `src/storage.ts`, `src/locks.ts`, and the emitted browser code. Include build scripts, vendored dependency provenance, browser behavior and deployment configuration when they affect a demonstrated path. Repository prose is not proof that a control is implemented.

## Vault protection and exposed metadata

The vault derives a non-extractable Web Crypto AES-256-GCM key from the passphrase using PBKDF2-HMAC-SHA-256, 600,000 iterations and a random 16-byte salt. Each write uses a fresh random 12-byte IV. The passphrase is not intentionally stored by the application. A non-extractable key prevents ordinary API key export; it does not stop malicious code in an unlocked page from using the key or reading plaintext.

Record payloads encrypt private keys, public bundles, aliases, timestamps, message/media contents, ratchet state and replay-owner associations. Necessary query identifiers remain in cleartext: contact fingerprints, conversation IDs, message IDs and replay hashes. Record counts, ciphertext sizes, store layout, IVs, salt, iteration count and vault identifier are also exposed. Someone holding a database copy can attempt offline password guesses.

The vault enforces a five-minute inactivity deadline beginning on creation/unlock. Trusted pointer/keyboard activity renews it only before expiry; storage reads and rendering do not. Storage snapshots, asynchronous access guards, status queries, timer callbacks and resumed UI/lifecycle events check expiration. Wall-clock and monotonic elapsed time are both bounded; backwards or invalid readings fail closed. Timers may be delayed while browser execution is suspended, so this does not guarantee immediate screen clearing during suspension. Manual lock and `pagehide` handling remain available. BroadcastChannel distributes lock requests to other tabs when supported. Buffer clearing and dropping key references are best effort: JavaScript garbage collection, immutable strings, browser internals, operating-system memory management and extensions prevent a guarantee of memory erasure.

## Identity continuity and retention defaults

A new vault creates its identity and password verifier in one transaction. The encrypted verifier binds all identity key material. Existing-vault unlock decrypts and validates identity before publishing the candidate key; missing, corrupt or mismatched identity fails closed. Every storage transaction checks the current identity envelope alongside metadata, and ordinary storage APIs cannot replace or remove `identity/local`. `getLocalIdentity()` only reads existing keys.

The exact legacy verifier is accepted only with a present, authenticated, correctly shaped identity. Its first successful unlock atomically upgrades only the verifier, preserving all identity and data records. Other old tabs must be closed and the current build used thereafter. This authenticates the pairing at migration time; it cannot establish historical freshness or discover an earlier coherent whole-vault rollback. An interrupted older creation that left only metadata is incomplete and is not silently repaired.

New plaintext history is opt-in per peer (`saveHistory === true`), read under the same state lock as the ratchet commit. Temporary messages never enter the message store, but remain in the sending/importing tab's bounded memory until lock/reload/close/eviction. Existing saved history is preserved unless explicitly cleared. Clearing a peer's history preserves session and replay state and sends only a public peer identifier and vault identifier through the cross-tab notification channel, never plaintext. Page controls request no browser spellchecking/translation; they cannot govern extensions or privileged browser/OS services.

## Limits and non-goals

- **No blanket cryptographic assurance.** X25519, ML-KEM-1024, Ed25519, ML-DSA-87, HKDF/HMAC-SHA-256, AES-256-GCM-SIV for packets and AES-256-GCM for vault records are components of a custom composition here. Do not claim proven forward secrecy, post-compromise recovery, quantum security or non-repudiation for this application. Explicitly saved or previously retained local plaintext history remains readable to someone who can unlock the vault.
- **No protection from compromised endpoints or delivered code.** Malware, malicious extensions, modified first-party scripts, debugging access and hostile hosting can capture passphrases, plaintext or keys. CSP and a non-extractable vault key do not remove this trust boundary.
- **No anonymity or metadata-hiding transport.** Public identity bundles, conversation IDs, counters, ratchet public parameters, timing, recipient routing and packet sizes can be observed. The host also sees ordinary requests when the app is served remotely.
- **No clipboard or recipient erasure.** Clipboard history/synchronization, other applications, screenshots, recipient copies and external transports are outside vault control.
- **No secure deletion guarantee.** Database deletion is logical deletion. It cannot guarantee erasure from browser/OS backups, filesystem snapshots, storage media or previously copied data. Legacy `ECP_DB` records remain until the user explicitly deletes them on the relevant origin/profile.
- **Replay records deliberately persist.** Peer deletion and channel reset retain replay records. Destroying the entire vault removes them with the identity. They can grow over time and have no automatic expiry policy.
- **No rollback-resistant storage or session cloning.** At-rest AEAD detects tampering with authenticated records; it cannot prove the freshness of an entire valid database snapshot. There is no trusted external monotonic counter. Restoring old state or simultaneously using cloned profiles can repeat sending-chain keys and counters and restore old replay history. The v3 wire uses fresh random 96-bit nonces and AES-256-GCM-SIV to reduce the confidentiality/integrity damage from nonce reuse; it does not detect rollback, restore missing replay records, or prevent forked histories. A compromised randomness source remains dangerous, and nonce misuse resistance does not justify deliberate reuse. Do not clone or restore active session databases. After a profile restore, retire the restored identity and establish fresh identities and independently verified channels. Browser-profile copying is not a supported backup or migration workflow.
- **No backup or recovery feature.** There is no supported key backup, vault export/import, passphrase reset/change or account recovery. Storage loss or a forgotten passphrase can be permanent.
- **No availability or delivery guarantee.** Users move packets manually. Lost packets, exhausted skip budgets, locked storage, browser quotas or unavailable clipboard permissions can interrupt communication. Local history is not proof of remote receipt.
- **No engine-side-channel guarantee.** The application does not establish constant-time execution, secure memory isolation or side-channel resistance across JavaScript engines and devices.

These boundaries must not be used to dismiss an in-scope bug that lets an untrusted packet obtain the same privileges, an incorrect deletion/lock behavior, or an application-controlled leak of sensitive data.

## Verification and independent review

Downloaded CI packages have a separate provenance boundary. A deterministic archive contains only the validated static client and explicit support files; its filesystem ownership, timestamps and permissions are normalized. A separate GitHub-hosted job may sign only after the verification job succeeds on a push to `ffookk/ecp` at `refs/heads/main`. This job has no checkout or dependency execution, and consumes the producing upload's artifact ID from the same run. Pull requests and manual runs receive no signing permissions. A successful signed-package upload requires verification of the actual shipped bundle, including repository, signer workflow, source ref, full source commit and hosted-runner policy; mismatched inputs, changed bytes and malformed bundles must reject.

Consumers must verify the archive with independently trusted tooling before extracting or executing included code, and choose the expected full commit outside the archive. See [verification instructions](https://github.com/ffookk/ecp/blob/main/docs/VERIFYING_RELEASES.md) in the source repository. The bundle is public build metadata and is not a private user-data backup. GitHub/Sigstore signing and online verification are network operations; public transparency records persist. Attestations do not establish protocol safety, dependency safety, build reproducibility or release freshness, and cannot prevent a compromised authorized build from attesting harmful output. Verification covers the checked archive bytes at that time; local modification after verification remains an endpoint trust boundary.

The Node suite includes RFC 8452 AES-256-GCM-SIV known-answer vectors and synthetic snapshot/fork regressions, in addition to protocol, storage, concurrency and lifecycle checks. The browser suite runs in Chromium, Firefox and WebKit using isolated profiles and a page-local clipboard. These are implementation checks, not an independent cryptographic audit. See [docs/PROTOCOL.md](docs/PROTOCOL.md) for review-oriented framing and state notes.

Before claiming suitability for important private communications, the outstanding work includes independent review of the complete key schedule/authentication/ratchet composition, audit of the supported release artifacts and browser lifecycle, and a sustained maintenance and vulnerability-response record. Automated tests, an AI-assisted review, known-answer vectors, and use of established primitives do not substitute for this evidence. No such independent result is claimed by this repository.

## Reporting a vulnerability

Report fork-specific issues to the maintainers of the repository containing this file. If that repository has GitHub private vulnerability reporting enabled, use its **Security → Report a vulnerability** flow. If no private reporting channel is available, open a minimal issue asking for one before sharing exploit details that could expose users. Do not assume that the upstream maintainer operates or endorses this fork.

Include the affected commit, browser/OS and Node versions when relevant, an isolated reproduction using synthetic identities and messages, the attacker prerequisites, expected versus observed behavior, and the specific source-to-impact path. Distinguish a reproduced result from a static candidate or design question. Do not attach real passphrases, private keys, browser profiles, personal message history or third-party data.

Do not test other users, the upstream deployment or a public hosted instance without separate authorization. Use isolated local profiles and synthetic data. There is no bug bounty or response-time commitment stated by this project.
