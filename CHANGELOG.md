# Changelog

Changes below describe this experimental fork of [jamesliu96/ecp](https://github.com/jamesliu96/ecp). They do not describe an upstream release or an independent security certification.

## 1.3.1

- Enforce the five-minute inactivity deadline in the vault access layer using both wall-clock and monotonic elapsed time. Expired activity cannot renew access, background reads do not renew it, and clock rollback/nonfinite readings fail closed.
- Recheck expiry on resumed focus, visibility and page lifecycle events, and before trusted input reaches sensitive controls. Browser execution suspension can still delay visual cleanup.
- Cancel queued peer deletion or channel wipe when the confirmation modal or selected peer changes before the mutation begins. Preserve already committed transaction semantics.
- Add synthetic elapsed-time, deferred-crypto, cross-tab locking and queued-cancellation regressions. These hardening checks do not establish natural browser sleep ordering or independent protocol assurance.
- Keep wire v3, identity fingerprints and encrypted-vault schema unchanged. No user data migration is performed by this release.

## 1.3.0 — Unreleased

- Create vault metadata and local identity atomically; stop on missing or corrupt identity instead of silently generating replacement keys. Authenticate identity material in the verifier, validate it before unlocking, and pin the identity envelope during storage transactions.
- Upgrade intact legacy verifiers without changing their identity or data records. Old builds cannot unlock the upgraded verifier; use this build in every tab. Incomplete older initialization is rejected without automatic repair.
- Make new plaintext message history opt-in per peer. Keep default messages only in bounded, tab-local memory until lock/reload/close/eviction while still durably advancing the ratchet.
- Add explicit history preferences and all-channel peer-history clearing. Preserve old saved history until explicit deletion, and preserve session/replay state when clearing history.
- Request no spellchecking, autocorrection or translation for sensitive content; correct an inherited broad post-quantum UI claim and repair protocol derivation documentation.
- Add synthetic identity-corruption, creation-abort, legacy-upgrade, policy, transient-history and browser lifecycle regressions. These changes do not replace independent protocol and application review.

## 1.2.0 — Unreleased

### Wire v3 and snapshot misuse resistance

- Replace deterministic AES-GCM wire nonces with internally generated random 96-bit nonces and AES-256-GCM-SIV. Synthetic restoration of an established v2 sending chain reproduced repeated key/nonce use and ciphertext-XOR disclosure; the v3 regression tests both restored and forked senders.
- Introduce incompatible `e2e3:` / `E2E3` framing, wire version 3 and v3 KDF/transcript domains. Reject v2 wire packets; keep the v2 encrypted-vault schema, identity format and fingerprint domain unchanged.
- Disable sending on stored v2 channels and require an explicit channel reset on both peers. The reset deletes that peer's local history; installing the upgrade does not delete it automatically.
- Add RFC 8452 AES-256-GCM-SIV known-answer vectors, strict nonce/ciphertext/AAD tamper tests, RNG-failure checks and snapshot regressions. This mitigates nonce misuse, not snapshot rollback, forked histories or erased replay protection.

### Operation lifetime and delivery

- Capture vault access before protocol and identity operations enter a lock queue; reject work crossing a lock/unlock cycle, including a cycle completed before the queue resumes.
- Bind peer import, alias editing, metadata and clipboard completions to their initiating UI state. Invalidate stale modals and prevent a delayed alias operation from changing another peer's visible title.
- Add real-browser regressions for delayed operations and protocol upgrade handling; run the suite in Chromium, Firefox and WebKit in CI.
- Initialize modal focus synchronously so delayed animation frames cannot redirect fingerprint entry. Disable vault form input while deletion, durable status loading or a submission is pending.
- Add an offline runnable package with a loopback server and checksum manifests; restrict CI artifacts to the intended package. No automatic deployment is added.
- Add a publication privacy gate for staged files, reachable history and commit metadata, with synthetic regression fixtures generated outside the checkout.
- Document protocol framing, derivation, snapshot limitations and remaining independent-review requirements. Experimental status is retained.

## 1.1.0 — Unreleased

### Breaking changes

- Introduce incompatible v2 framing (`e2e2:`, `E2E2`, wire version 2) and version-specific cryptographic domain separators.
- Create a fresh identity in `ECP_SECURE_DB_v2`; do not automatically import v1 identity keys, plaintext history or sessions. Participants must exchange and independently verify new fingerprints.
- Make INIT a control-only packet. Require explicit handshake initiation and response processing before the initiator sends message content.
- Require Web Locks and Web Crypto in a secure context instead of falling back to per-tab protocol synchronization.
- Replace the previous persistence setting with a passphrase-protected local vault. No backup, passphrase change, import or recovery feature is introduced.

### Protocol and state integrity

- Serialize public protocol operations across same-origin tabs, reading current session state while holding the lock.
- Commit ratchet advancement and message history in one batch; commit accepted handshake state and replay records together.
- Preserve the new receiving chain after a DH ratchet transition instead of overwriting it with an older staged chain.
- Bound both previous-chain and new-chain skip requests, including their combined budget, before key-skipping or DH/KEM work. Limit retained skipped keys to 100.
- Enforce exact packet framing, decoded-size limits, counter checks and exhaustion handling.
- Reject unknown or unverified handshake senders, identity mismatches, content-bearing INIT packets and attempts to replace an active channel.
- Track handshake replays by authenticated transcript in a separate store that survives peer deletion and channel reset, without the former 100-entry history truncation.
- Replace arbitrary established-session RESP fallback with matching pending-handshake authentication or an exact previously accepted response hash.
- Clear selected operation-local derived buffers on a best-effort basis; do not claim JavaScript memory erasure.

### Local privacy and lifecycle

- Encrypt vault payloads with AES-256-GCM, fresh random 12-byte IVs and record/vault/store/index authentication binding.
- Derive the vault key with PBKDF2-HMAC-SHA-256, 600,000 iterations and a random 16-byte salt. Retain required record identifiers and query indices in cleartext.
- Add vault creation/unlock, a manual lock, a five-minute inactivity timer, page lifecycle locking and cross-tab lock notifications where supported.
- Invalidate operations and tracked transactions when vault state changes; reject corrupt metadata and failed unlocks without silently recreating the vault.
- Delete peer histories by peer association across conversations. Retain replay records deliberately until whole-vault deletion.
- Detect legacy plaintext storage without opening it for reading, and offer an explicit legacy-deletion action. Logical deletion is not secure erasure.

### UI, build and verification

- Bind asynchronous attachment reads and chat rendering to the selected recipient and vault generation; discard stale completions after switching peers or locking. Clear drafts on peer changes.
- Require the full independently confirmed fingerprint when linking a peer, and explain why a fingerprint supplied with the same untrusted bundle is insufficient.
- Display experimental status, passphrase/recovery limitations and local-vault boundaries.
- Pin runtime and development dependencies in the lockfile, support installation with lifecycle scripts disabled, build static assets into `dist/`, and generate an artifact checksum manifest.
- Provide a loopback-only development server with restrictive response headers and a page content security policy.
- Remove automatic service-worker registration/update behavior and include a retirement worker for older cached deployments. Do not deploy to GitHub Pages automatically.
- Add Node protocol/vault regression tests and Playwright browser integration tests, including real same-origin tab concurrency and synthetic clipboard exchange.
- Replace the earlier broad security claims and v1-only README with v2 usage, threat boundaries and a security review/reporting policy.

### Remaining limitations

This release remains independently unaudited and uses a custom protocol. No blanket forward-secrecy, post-compromise recovery, quantum-security, anonymity or non-repudiation guarantee is made. Hosting origin integrity, endpoint integrity, exposed database/transport metadata, clipboard history, logical-deletion limits and lack of recovery remain material boundaries documented in [SECURITY.md](SECURITY.md). Restoring or simultaneously using cloned active-session databases can repeat ratchet keys and nonces; at-rest authentication does not establish whole-snapshot freshness. Use fresh identities after a profile restore.
