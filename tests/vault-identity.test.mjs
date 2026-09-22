import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { indexedDB, IDBKeyRange, IDBObjectStore } from 'fake-indexeddb';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
});
Object.assign(globalThis, { indexedDB, IDBKeyRange });
const queues = new Map();
Object.defineProperty(globalThis, 'navigator', {
  configurable: true,
  value: {
    locks: {
      request(name, action) {
        const pending = (queues.get(name) ?? Promise.resolve()).then(action);
        queues.set(
          name,
          pending.catch(() => {}),
        );
        return pending;
      },
    },
  },
});
const { DB, Vault } = await import('../storage.js');
const { getLocalIdentity, calculateFingerprint, serializeIdentityPublic } =
  await import('../identity.js');
const { createIdentityMaterial } = await import('../identity-material.js');
const passphrase = 'synthetic identity continuity passphrase';
const databaseName = 'ECP_SECURE_DB_v2';
const encoder = new TextEncoder();
const request = (req) =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
async function raw(stores, mode, action) {
  const db = await request(indexedDB.open(databaseName, 1));
  try {
    const tx = db.transaction(stores, mode);
    const done = new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onabort = () => reject(tx.error ?? new Error('aborted'));
    });
    const result = await action(tx);
    await done;
    return result;
  } finally {
    db.close();
  }
}
const read = (store, id) =>
  raw([store], 'readonly', (tx) => request(tx.objectStore(store).get(id)));
const fingerprint = async () =>
  calculateFingerprint(serializeIdentityPublic(await getLocalIdentity()));
function pauseCrypto(method, targetCall) {
  const original = webcrypto.subtle[method];
  let resume, entered;
  let calls = 0;
  const ready = new Promise((resolve) => {
    entered = resolve;
  });
  const waiting = new Promise((resolve) => {
    resume = resolve;
  });
  webcrypto.subtle[method] = async function (...args) {
    const result = await original.apply(this, args);
    if (++calls === targetCall) {
      entered();
      await waiting;
    }
    return result;
  };
  return {
    ready,
    release() {
      webcrypto.subtle[method] = original;
      resume();
    },
  };
}
async function setup() {
  await Vault.destroy();
  await Vault.create(passphrase);
}
async function keyFor(metadata) {
  const material = await webcrypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return webcrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: metadata.salt,
      iterations: metadata.iterations,
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
function metaAAD(m) {
  return encoder.encode(
    JSON.stringify([
      databaseName,
      2,
      'meta',
      'vault',
      m.vaultId,
      Array.from(m.salt),
      m.iterations,
    ]),
  );
}
async function setVerifier(text) {
  const metadata = await read('meta', 'vault');
  metadata.iv = webcrypto.getRandomValues(new Uint8Array(12));
  metadata.ciphertext = new Uint8Array(
    await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metadata.iv, additionalData: metaAAD(metadata) },
      await keyFor(metadata),
      encoder.encode(text),
    ),
  );
  await raw(['meta'], 'readwrite', (tx) =>
    request(tx.objectStore('meta').put(metadata)),
  );
  return metadata;
}
function encode(value) {
  if (value instanceof Uint8Array)
    return ['Uint8Array', Buffer.from(value).toString('base64')];
  if (typeof value === 'object' && value !== null)
    return ['object', Object.entries(value).map(([k, v]) => [k, encode(v)])];
  return ['p', value];
}

test('vault identity continuity', async (t) => {
  t.after(() => Vault.destroy());
  await t.test(
    'explicit creation atomically creates stable keys and rejects generic key replacement',
    async () => {
      await setup();
      const before = await fingerprint();
      assert.equal((await DB.getAll('identity')).length, 1);
      await assert.rejects(
        DB.put('identity', createIdentityMaterial()),
        /only be created/,
      );
      await assert.rejects(DB.delete('identity', 'local'), /entire vault/);
      Vault.lock();
      await Vault.unlock(passphrase);
      assert.equal(await fingerprint(), before);
    },
  );
  await t.test(
    'deleting identity from a locked populated vault never regenerates it or changes surviving records',
    async () => {
      await setup();
      await DB.put('contacts', {
        fingerprint: 'synthetic-peer',
        bundle: 'synthetic',
        name: 'Synthetic',
        verified: false,
        archived: false,
        lastReadTimestamp: 0,
      });
      const metadata = await read('meta', 'vault'),
        contact = await read('contacts', 'synthetic-peer');
      Vault.lock();
      await raw(['identity'], 'readwrite', (tx) =>
        request(tx.objectStore('identity').delete('local')),
      );
      await assert.rejects(Vault.unlock(passphrase), /identity.*missing/);
      await assert.rejects(getLocalIdentity(), /locked/);
      assert.equal(Vault.isUnlocked(), false);
      assert.equal(await read('identity', 'local'), undefined);
      assert.deepEqual(await read('meta', 'vault'), metadata);
      assert.deepEqual(await read('contacts', 'synthetic-peer'), contact);
    },
  );
  await t.test(
    'identity deletion while unlocked invalidates all storage operations before a write',
    async () => {
      await setup();
      await raw(['identity'], 'readwrite', (tx) =>
        request(tx.objectStore('identity').delete('local')),
      );
      await assert.rejects(
        DB.put('replays', { id: 'must-not-commit', contactFp: 'synthetic' }),
        /identity/,
      );
      assert.equal(Vault.isUnlocked(), false);
      assert.equal(await read('replays', 'must-not-commit'), undefined);
      assert.equal(await read('identity', 'local'), undefined);
    },
  );
  await t.test(
    'failure of either creation insert rolls back identity and metadata',
    async () => {
      for (const failedStore of ['meta', 'identity']) {
        await Vault.destroy();
        const add = IDBObjectStore.prototype.add;
        IDBObjectStore.prototype.add = function (...args) {
          if (this.name === failedStore)
            throw new Error('synthetic creation abort');
          return add.apply(this, args);
        };
        try {
          await assert.rejects(
            Vault.create(passphrase),
            /synthetic creation abort/,
          );
        } finally {
          IDBObjectStore.prototype.add = add;
        }
        assert.equal(Vault.isUnlocked(), false);
        assert.equal(await read('identity', 'local'), undefined);
        assert.equal(await read('meta', 'vault'), undefined);
      }
    },
  );
  await t.test(
    'an intact legacy verifier upgrades only metadata without changing identity or other records',
    async () => {
      await setup();
      const before = await fingerprint(),
        identity = await read('identity', 'local');
      await DB.put('replays', {
        id: 'retained-replay',
        contactFp: 'synthetic',
      });
      const replay = await read('replays', 'retained-replay');
      Vault.lock();
      const legacy = await setVerifier('ecp-password-vault-v2');
      await Vault.unlock(passphrase);
      assert.equal(await fingerprint(), before);
      assert.deepEqual(await read('identity', 'local'), identity);
      assert.deepEqual(await read('replays', 'retained-replay'), replay);
      const updated = await read('meta', 'vault');
      assert.notDeepEqual(updated.ciphertext, legacy.ciphertext);
      const text = new TextDecoder().decode(
        await webcrypto.subtle.decrypt(
          { name: 'AES-GCM', iv: updated.iv, additionalData: metaAAD(updated) },
          await keyFor(updated),
          updated.ciphertext,
        ),
      );
      assert.match(
        text,
        /^ecp-password-vault-v2:identity-v1:[A-Za-z0-9_-]{43}$/,
      );
      Vault.lock();
      await Vault.unlock(passphrase);
      assert.equal(await fingerprint(), before);
    },
  );
  await t.test(
    'incomplete legacy initialization and unknown verifier formats stay locked without migration',
    async () => {
      for (const text of [
        'ecp-password-vault-v2',
        'ecp-password-vault-v2:identity-v1:invalid',
      ]) {
        await setup();
        Vault.lock();
        const metadata = await setVerifier(text);
        if (text === 'ecp-password-vault-v2')
          await raw(['identity'], 'readwrite', (tx) =>
            request(tx.objectStore('identity').delete('local')),
          );
        await assert.rejects(Vault.unlock(passphrase));
        assert.equal(Vault.isUnlocked(), false);
        assert.deepEqual(await read('meta', 'vault'), metadata);
      }
    },
  );
  await t.test(
    'authenticated replacement key material fails the verifier binding',
    async () => {
      await setup();
      Vault.lock();
      const metadata = await read('meta', 'vault'),
        replacement = createIdentityMaterial();
      const iv = webcrypto.getRandomValues(new Uint8Array(12));
      const aad = encoder.encode(
        JSON.stringify([
          databaseName,
          2,
          metadata.vaultId,
          'identity',
          'local',
          null,
          null,
          null,
        ]),
      );
      const ciphertext = new Uint8Array(
        await webcrypto.subtle.encrypt(
          { name: 'AES-GCM', iv, additionalData: aad },
          await keyFor(metadata),
          encoder.encode(JSON.stringify(encode(replacement))),
        ),
      );
      await raw(['identity'], 'readwrite', (tx) =>
        request(
          tx
            .objectStore('identity')
            .put({ schema: 2, id: 'local', iv, ciphertext }),
        ),
      );
      await assert.rejects(Vault.unlock(passphrase), /authenticated binding/);
      assert.equal(Vault.isUnlocked(), false);
      assert.deepEqual(await read('meta', 'vault'), metadata);
    },
  );
  await t.test(
    'typed-array identity envelope lookalikes cannot bypass the live continuity guard',
    async () => {
      for (const field of ['iv', 'ciphertext']) {
        await setup();
        const original = await read('identity', 'local');
        const malformed = { ...original, [field]: { ...original[field] } };
        assert.equal(JSON.stringify(malformed), JSON.stringify(original));
        await raw(['identity'], 'readwrite', (tx) =>
          request(tx.objectStore('identity').put(malformed)),
        );
        await assert.rejects(
          DB.put('replays', { id: 'no-write', contactFp: 'synthetic' }),
          /identity/,
        );
        assert.equal(Vault.isUnlocked(), false);
        assert.equal(await read('replays', 'no-write'), undefined);
        await assert.rejects(Vault.unlock(passphrase));
        assert.equal(Vault.isUnlocked(), false);
      }
    },
  );
  await t.test(
    'concurrent creation leaves exactly one complete usable vault',
    async () => {
      await Vault.destroy();
      const results = await Promise.allSettled([
        Vault.create(passphrase),
        Vault.create(passphrase),
      ]);
      assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
      assert.equal((await DB.getAll('identity')).length, 1);
      const before = await fingerprint();
      Vault.lock();
      await Vault.unlock(passphrase);
      assert.equal(await fingerprint(), before);
    },
  );
  await t.test(
    'locking during identity authentication cannot publish a provisional key',
    async () => {
      await setup();
      Vault.lock();
      // The first decrypt verifies the password; the second decrypts identity.
      const gate = pauseCrypto('decrypt', 2);
      const pending = Vault.unlock(passphrase);
      const rejected = assert.rejects(pending, /locked/);
      await gate.ready;
      assert.equal(Vault.isUnlocked(), false);
      Vault.lock();
      gate.release();
      await rejected;
      assert.equal(Vault.isUnlocked(), false);
      await Vault.unlock(passphrase);
      assert.equal((await DB.getAll('identity')).length, 1);
    },
  );
  await t.test(
    'creation refuses raw data inserted during encryption and preserves it unchanged',
    async () => {
      await Vault.destroy();
      const gate = pauseCrypto('encrypt', 1);
      const pending = Vault.create(passphrase);
      const rejected = assert.rejects(pending, /already contains data/);
      await gate.ready;
      const foreign = {
        fingerprint: 'synthetic-concurrent-record',
        marker: 'preserve-on-failure',
      };
      await raw(['contacts'], 'readwrite', (tx) =>
        request(tx.objectStore('contacts').put(foreign)),
      );
      gate.release();
      await rejected;
      assert.equal(Vault.isUnlocked(), false);
      assert.equal(await read('identity', 'local'), undefined);
      assert.equal(await read('meta', 'vault'), undefined);
      assert.deepEqual(await read('contacts', foreign.fingerprint), foreign);
    },
  );
});
