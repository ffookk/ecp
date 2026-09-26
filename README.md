# ECP Hardened — Experimental

A security-focused fork of [James Liu's E2EE Clipboard Protocol](https://github.com/jamesliu96/ecp). ECP is a browser application for manually exchanging encrypted messages and media through another transport, such as a messenger or email. It has no application messaging backend: you copy an encoded packet, deliver it yourself, and ask the recipient to read it.

**This is experimental software with a custom, independently unaudited protocol.** The changes in this fork address concrete implementation problems and add regression tests. They do not establish that the protocol is suitable for high-risk communications or make it equivalent to an independently reviewed messaging system. See [SECURITY.md](SECURITY.md) for the threat model and remaining limits.

## Compatibility and current status

- This fork uses the incompatible **v3** wire format: `e2e3:` envelopes, `E2E3` packet magic, and protocol version `3`.
- Existing v2 encrypted vaults, identities and verified contacts are retained. This build adds an encrypted identity binding to the password verifier on the first successful unlock of an intact older vault; use this build in every tab after upgrading. Older builds cannot unlock the upgraded verifier. Missing or corrupt identity records stop unlock without generating replacement keys. Identity fingerprints do not change. Existing v2 channels cannot send or accept v3 packets: upgrade both participants, then explicitly use **Wipe Channel State** on both sides before a new handshake. Wiping deletes that peer's local history; the upgrade itself does not. v1 plaintext identities and history are never imported automatically.
- There is no built-in backup, export/import, passphrase change, or recovery mechanism. Losing the passphrase, clearing browser storage, losing the browser profile, or browser storage eviction can permanently lose the identity and history.
- Do not clone or restore an active session database. Restoring or simultaneously using copies can repeat ratchet keys, counters and replay history. Random wire nonces and AES-256-GCM-SIV mitigate nonce-reuse damage but do not authenticate snapshot freshness or make cloning safe. Use fresh identities and newly verified channels after a profile restore; vault encryption cannot establish the freshness of an entire valid database snapshot.
- The implementation remains subject to independent protocol review and further hardening. The software and tests are not a security certification.

## Run a local build

Use Node.js **22 or newer**, npm, and a current browser with Web Crypto, IndexedDB, Web Locks, and clipboard support in a secure context. The bundled server uses the loopback interface; HTTPS is required when serving from a non-local origin. Browser permissions can affect clipboard access. The UI also depends on IndexedDB database enumeration to detect legacy data safely.

From a checkout of this fork:

```sh
npm ci --ignore-scripts
npm run check
npm run dev
```

Open [the local app](http://127.0.0.1:4173). `npm run check` runs TypeScript checking, a production build, and Node tests against the resulting code. `npm run dev` serves the existing `dist/` directory at `127.0.0.1:4173`; it is not a build watcher. After changing source files, build again with `npm run build` and reload the page.

The build copies pinned Noble dependencies from the lockfile into local browser assets and writes `dist/SHA256SUMS.json`. These hashes help compare build artifacts; they are not a signed release attestation and do not authenticate a compromised build machine or hosting origin. Installing dependencies and running builds still requires trust in the selected source, package registry, lockfile, and local tooling.

**Building and testing do not publish anything.** There is no automatic GitHub Pages deployment. Review any hosting decision separately and serve only the intended built artifacts.

## Package for local use

```sh
npm run package
cd build-package
node scripts/serve.mjs
```

The package contains the static application, a Node-only loopback server, usage notes and checksum manifests. No npm installation or runtime network dependency is needed to run the generated package. Keep the same local origin and browser profile to access an existing vault; changing the port or origin creates a separate storage scope. This is not a vault backup.

CI uploads the explicit `build-package/` directory after its checks. It does not upload browser profiles, clipboard contents, test traces or the whole workspace, and it does not deploy the app. Checksums detect changes only relative to a trusted manifest; they are not a publisher signature.

Before publishing, stage only intended project files and run `npm run privacy:check`. This checks the staged index, reachable Git history and commit metadata for common secret/path patterns and unintended files. New commit email addresses must use GitHub's noreply form; reviewed upstream history retains its original public authors. Pattern checks can miss unknown secret formats and cannot anonymize a public GitHub account.

## Exchange a message

1. Create a vault on each participant's browser. Choose a strong, unique passphrase; the application requires at least 12 characters, but length alone does not make a passphrase resistant to guessing. Keep it somewhere appropriate because there is no recovery.
2. Use **Copy Identity Bundle** to exchange public bundles. On each side, choose **Link New Peer**, set a local alias, and enter the full fingerprint independently confirmed by that person. Compare through a separate trusted channel, such as an in-person conversation. A fingerprint delivered alongside the bundle on the same untrusted channel does not authenticate it.
3. One participant selects the peer and starts the handshake. Deliver the copied **INIT** packet to the other participant, who selects **Read Clipboard Packet** or pastes the packet outside an input field. Both peers must already have verified each other's identities.
4. Deliver the recipient's copied **RESP** packet back to the initiator and read it. INIT contains no user message. The initiator must process the response before sending message content.
5. Compose a message or attach supported media, send it, and deliver the resulting encrypted packet. The recipient reads the packet to decrypt it. A copied packet or a locally displayed outgoing message is not a delivery receipt.

The decoded input envelope is limited to 1 MiB, including protocol overhead. The UI limits selected media files to 700,000 bytes because data URLs and packet encoding add overhead. Large gaps in message delivery can be rejected: the protocol limits each operation to a combined 100 skipped positions and keeps at most 100 skipped message keys. Retain the original transport packets if you need to retry delivery; the application is not a reliable transport or synchronization service.

To restart a channel, use **Wipe Channel State** on both sides before starting a new handshake. This deletes that peer's local session and message history while retaining the contact and handshake replay records. An incoming INIT cannot silently replace an active channel.

## Message history defaults

New message text and media are **not saved to the vault by default**, including for existing contacts without an explicit saving preference. Ratchet state and replay protection still persist and commit before a result is returned. Temporary messages are visible only in the tab that sent or imported them, until that tab locks, reloads, closes, or evicts old messages at its 100-message / 8 MiB content budget. The budget counts retained string contents and scalar fields, not total browser heap usage. There is no cross-tab plaintext synchronization.

To keep future messages, choose **Peer Options → Message History → Save new messages for this peer in the encrypted vault**. This is a local preference; it does not control the recipient's storage. Each send/receive reads the current preference inside the origin-wide state lock. Turning saving on does not save earlier temporary messages. Turning it off preserves existing saved records. Saved history is readable by anyone who can unlock the vault, regardless of ratchet key deletion.

**Clear all local history for this peer** explicitly deletes that peer's saved messages across all channels and clears temporary views in active tabs through the vault notification channel. It preserves the current channel, contact, replay protection and saving preference. Disabling saving or installing the upgrade never silently deletes existing history. Logical deletion cannot erase recipient copies, browser/OS backups, decoded buffers or forensic remnants.

The page requests that browser spellchecking, autocorrection and translation avoid its sensitive inputs/content. Browser preferences, extensions, operating-system input services and user-invoked translation can override or operate outside these page controls.

## Local vault and locking

Identity private keys, contact details, ratchet state, explicitly saved message text/media, and replay-record contents are encrypted in IndexedDB using a passphrase-derived AES-256-GCM key. The vault uses PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random 16-byte salt. Each encrypted write uses a fresh random 12-byte IV. Authentication binds each record to its vault, store, and public record identifiers.

Encryption does **not** conceal the whole database structure. Primary keys and required query indices remain visible, including contact fingerprints, conversation IDs, message IDs and replay-record hashes. Store names, record counts, ciphertext sizes, IVs, and password-derivation metadata are also visible. A copied vault allows offline passphrase guesses; choose a strong passphrase.

Use **Global Settings → Lock now** to lock manually. The vault expires after five minutes without trusted pointer/keyboard activity observed in that tab and locks on `pagehide`. Elapsed time is checked at storage/access boundaries, before activity can renew the deadline, and when focus or page visibility returns. Background reads and rendering do not renew access. Wall time and monotonic elapsed time are both checked; backwards or invalid clock readings lock conservatively. Locking removes the application's current vault-key reference, aborts tracked transactions, clears displayed conversation data, and broadcasts a lock request to other tabs when BroadcastChannel is available. Browser suspension and timer throttling can still delay the callback and screen clearing while JavaScript is not running. On resumption, expired access is rejected instead of granting another five minutes. Use the manual control before leaving sensitive content unattended.

An unlocked page can access plaintext. JavaScript strings, browser internals, garbage collection, device memory, swap, and browser extensions prevent a guarantee of memory erasure. Clearing selected buffers and hiding the UI do not make a compromised or previously inspected device safe.

Post-unlock view loading does not keep the authentication form busy. If the vault locks while an old view is still loading, that work cannot disable a later unlock or report an error into the new authentication attempt.

## Deletion, legacy data, and replay records

**Delete Peer & History** removes that peer's contact, session, and all indexed local message history. Handshake replay records intentionally survive peer deletion and channel reset so that an old recorded INIT is not accepted as a new handshake. These records occupy storage over time; there is no automatic expiry policy. Their peer association is encrypted, while the replay identifier remains a visible record key.

A peer deletion or channel wipe waiting for the state lock is canceled if its confirmation modal closes or the selection changes before the deletion transaction starts. Cancellation cannot undo a transaction that has already committed.

**Delete all local data** destroys the v2 vault, including its identity and replay records. This operation cannot be undone by the application.

If the old `ECP_DB` database is detected, the unlock screen offers a separate, explicit **Delete old unencrypted data** action. The fork does not open that database for reading or migrate its contents. Creating a new encrypted vault does not encrypt or delete old data. Close old ECP tabs if they block deletion. Legacy data on a different origin or in another browser profile must be managed there.

All deletion operations remove logical browser database records. They do not promise secure erasure from storage media, browser backups, filesystem snapshots, another device, a recipient's history, or the clipboard.

## Protocol implementation

The custom v3 protocol combines X25519, ML-KEM-1024, composite Ed25519 + ML-DSA-87 signatures, HKDF/HMAC-SHA-256 and AES-256-GCM-SIV for wire packets. The encrypted vault continues to use Web Crypto AES-256-GCM with independently random IVs. The wire primitives are implemented through pinned Noble libraries; using established primitives does not establish the security of their composition here.

The current implementation adds:

- Fresh random 96-bit nonces inside a shared AES-256-GCM-SIV packet wrapper; nonce generation failures abort without a weaker fallback.
- A control-only authenticated INIT and explicit response processing before the initiator sends content.
- Verified-contact checks, exact packet framing, strict version handling, and size/counter limits.
- An origin-wide Web Lock spanning each protocol read, cryptographic transition, and committed write. There is no weaker per-tab fallback.
- An access guard captured before queuing that invalidates protocol and identity operations across every lock/unlock cycle.
- Atomic encrypted batches for ratchet changes and message history, and for accepted handshakes and their replay records.
- Transcript-based handshake replay tracking, exact accepted-RESP duplicate matching, and bounded out-of-order message handling.

The wire layout, key schedule and state transitions are implemented in [src/codec.ts](src/codec.ts), [src/ratchet.ts](src/ratchet.ts), and [src/crypto.ts](src/crypto.ts). The [v3 protocol review notes](docs/PROTOCOL.md) describe framing, key derivation and state boundaries for external review. Do not reuse the protocol as a cryptographic standard without separate design and implementation review.

No blanket forward-secrecy, post-compromise recovery, quantum-security, anonymity, or non-repudiation guarantee is made. In particular, when plaintext message history has been explicitly saved inside the vault, an adversary who obtains the unlocked vault or its passphrase can read that retained history regardless of transport-key deletion.

## Hosting, transport, and clipboard boundaries

For evaluation, prefer a reviewed local build on a device and browser you control. A remote hosting origin can replace the HTML or JavaScript that processes passphrases and plaintext. A content security policy or encrypted database cannot protect you from malicious first-party code delivered by that origin. The current page does not register an automatically updating service worker; a retirement worker is included for older deployments. Existing browser workers and cached content may still need to be cleared when changing deployments.

The supplied application code has no messaging backend or analytics integration, but loading a hosted page still exposes ordinary web-request metadata to its host. The delivery service sees packet sizes, timing and routing. INIT exposes public identity bundles, and message packets expose conversation identifiers, ratchet public parameters and sequence counters. Those fields permit correlation.

Clipboard managers, clipboard synchronization, other applications, screenshots and recipients are outside vault control. Locking or deleting a vault does not remove already copied packets or plaintext from those places.

## Tests

Run the complete local check:

```sh
npm run check
```

Node regression tests exercise real protocol cryptography with isolated storage/lock adapters and exercise encrypted vault behavior with a test IndexedDB implementation. They cover multi-message ratchet turns, reordered and replayed packets, tampering, counter bounds, concurrent operations, transaction failures, vault locking and deletion. They do not constitute a cryptographic proof or exhaustive browser/OS coverage.

For the browser integration suite, install the three Playwright engines and run:

```sh
npx playwright install chromium firefox webkit
npm run test:browser
```

On Linux, Playwright may also require its documented browser system dependencies. A locally installed compatible Chromium browser can be selected with `ECP_BROWSER_PATH`; use `npm run test:browser -- --project=chromium` for only that engine. The override never replaces Firefox or WebKit. The suite builds the app, starts its own server on port 4173, and uses isolated browser contexts and a synthetic page-local clipboard. Stop any development server on that port first. It covers the visible vault/contact/handshake/message flow, wrong-passphrase handling, concurrent operations from real tabs sharing one origin, old-channel upgrade handling, and delayed operations across peer selection or vault lock/unlock. CI runs Chromium, Firefox and WebKit separately. Synthetic clipboard tests do not validate OS clipboard permissions or clipboard-history behavior.

## Attribution and license

This fork is derived from [jamesliu96/ecp](https://github.com/jamesliu96/ecp), originally authored by James Liu. The original copyright notice and [MIT license](LICENSE) are retained. Hardening changes in this fork are separate from upstream and do not imply upstream endorsement or an independent security audit.
