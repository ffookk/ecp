import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { indexedDB, IDBKeyRange, IDBObjectStore } from 'fake-indexeddb';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
});
Object.assign(globalThis, { indexedDB, IDBKeyRange });
const lockQueues = new Map();
Object.defineProperty(globalThis, 'navigator', {
  configurable: true,
  value: {
    locks: {
      request(name, action) {
        const result = (lockQueues.get(name) ?? Promise.resolve()).then(action);
        lockQueues.set(
          name,
          result.catch(() => {}),
        );
        return result;
      },
    },
  },
});
const { DB, Vault } = await import(
  process.env.ECP_STORAGE_MODULE
    ? pathToFileURL(process.env.ECP_STORAGE_MODULE).href
    : '../storage.js'
);
const passphrase = 'correct horse battery staple';
const databaseName = 'ECP_SECURE_DB_v2';
const stores = ['identity', 'contacts', 'sessions', 'messages', 'replays'];
const request = (req) =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
const committed = (tx) =>
  new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onabort = () => reject(tx.error ?? new Error('aborted'));
  });
async function raw(store, action, mode = 'readonly') {
  const db = await request(indexedDB.open(databaseName, 1));
  try {
    const tx = db.transaction(store, mode);
    const done = committed(tx);
    const result = await request(action(tx.objectStore(store)));
    await done;
    return result;
  } finally {
    db.close();
  }
}
const identity = () => ({
  id: 'me',
  ecSk: new Uint8Array([222, 173, 190, 239, 11, 27]),
  ecPk: new Uint8Array([1, 2]),
  dsaSk: new Uint8Array([3, 4]),
  dsaPk: new Uint8Array([5, 6]),
  dhSk: new Uint8Array([7, 8]),
  dhPk: new Uint8Array([9, 10]),
  kemSk: new Uint8Array([11, 12]),
  kemPk: new Uint8Array([13, 14]),
});
const contact = (fp = 'alice') => ({
  fingerprint: fp,
  bundle: 'private-bundle-sentinel',
  name: 'Secret Alice Name',
  verified: true,
  archived: false,
  lastReadTimestamp: 9876,
});
const session = (fp = 'alice', conversationId = 'conversation-1') => ({
  contactFp: fp,
  conversationId,
  version: 2,
  peerIdentity: 'private-peer-identity',
  DHs: { sk: new Uint8Array([21, 22]), pk: new Uint8Array([23, 24]) },
  RK: new Uint8Array([25, 26]),
  CKs: new Uint8Array([27, 28]),
  Ns: 1,
  Nr: 2,
  PN: 0,
  state: 'ESTABLISHED',
});
const message = (
  id = 'message-1',
  fp = 'alice',
  conversationId = 'conversation-1',
) => ({
  id,
  contactFp: fp,
  conversationId,
  isMe: true,
  text: 'secret-message-plaintext-sentinel',
  timestamp: 123456,
});
async function holdStateLock() {
  let release, started;
  const entered = new Promise((resolve) => {
    started = resolve;
  });
  const held = navigator.locks.request(
    `${databaseName}:state`,
    () =>
      new Promise((resolve) => {
        release = resolve;
        started();
      }),
  );
  await entered;
  return async () => {
    release();
    await held;
  };
}
function pauseCrypto(method) {
  const original = webcrypto.subtle[method];
  let resume, started;
  const waiting = new Promise((resolve) => {
    resume = resolve;
  });
  const entered = new Promise((resolve) => {
    started = resolve;
  });
  webcrypto.subtle[method] = async function (...args) {
    const result = await original.apply(this, args);
    started();
    await waiting;
    return result;
  };
  return {
    entered,
    release() {
      webcrypto.subtle[method] = original;
      resume();
    },
  };
}

test('encrypted storage and vault security boundaries', async (t) => {
  await t.test(
    'requires a strong passphrase and a vault before access',
    async () => {
      await Vault.destroy();
      assert.equal(await Vault.status(), 'new');
      await assert.rejects(Vault.create('short'), /12 characters/);
      await assert.rejects(DB.get('identity', 'me'), /locked/);
      await Vault.create(passphrase);
      assert.equal(await Vault.status(), 'unlocked');
      await assert.rejects(Vault.create(passphrase), /already exists/);
    },
  );

  await t.test(
    'access captured before lock cannot authorize work after unlocking',
    async () => {
      const stale = Vault.captureAccess();
      stale();
      Vault.lock();
      assert.throws(stale, /locked/);
      await Vault.unlock(passphrase);
      assert.throws(stale, /locked/);
      Vault.captureAccess()();
    },
  );

  await t.test(
    'encrypts every store with independent IVs; private bytes and text do not persist',
    async () => {
      const entries = [
        ['identity', identity()],
        ['contacts', contact()],
        ['sessions', session()],
        ['messages', message()],
        ['replays', { id: 'replay-1', contactFp: 'private-replay-owner' }],
      ];
      await DB.putMany(entries);
      const ivs = new Set();
      for (const [store, original] of entries) {
        const envelope = await raw(store, (objectStore) =>
          objectStore.get(
            original.id ?? original.fingerprint ?? original.contactFp,
          ),
        );
        assert.equal(envelope.schema, 2);
        assert.equal(envelope.iv.length, 12);
        assert(envelope.ciphertext instanceof Uint8Array);
        assert(envelope.ciphertext.length > 16);
        ivs.add(Buffer.from(envelope.iv).toString('hex'));
        const serialized = JSON.stringify(envelope);
        for (const secret of [
          'private-bundle-sentinel',
          'Secret Alice Name',
          'private-peer-identity',
          'secret-message-plaintext-sentinel',
          'private-replay-owner',
          'ecSk',
          'DHs',
          'lastReadTimestamp',
        ])
          assert(!serialized.includes(secret));
        assert.deepEqual(
          await DB.get(
            store,
            original.id ?? original.fingerprint ?? original.contactFp,
          ),
          original,
        );
      }
      assert.equal(ivs.size, entries.length);
      const persistedIdentity = await raw('identity', (objectStore) =>
        objectStore.get('me'),
      );
      assert.equal(
        Buffer.from(persistedIdentity.ciphertext).indexOf(
          Buffer.from(identity().ecSk),
        ),
        -1,
      );
      const metadata = await raw('meta', (objectStore) =>
        objectStore.get('vault'),
      );
      assert.equal(metadata.iterations, 600_000);
      assert.equal(metadata.salt.length, 16);
      assert(!JSON.stringify(metadata).includes(passphrase));
      assert.deepEqual(Object.keys(persistedIdentity).sort(), [
        'ciphertext',
        'id',
        'iv',
        'schema',
      ]);
    },
  );

  await t.test(
    'lock/reopen restores typed arrays and rejects a wrong password',
    async () => {
      Vault.lock();
      assert.equal(await Vault.status(), 'locked');
      await assert.rejects(DB.getAll('contacts'), /locked/);
      await assert.rejects(Vault.unlock('incorrect password but long enough'));
      assert.equal(Vault.isUnlocked(), false);
      await Vault.unlock(passphrase);
      assert.deepEqual(await DB.get('identity', 'me'), identity());
      assert((await DB.get('sessions', 'alice')).DHs.sk instanceof Uint8Array);
      assert.equal(
        (await DB.getByIndex('sessions', 'conversationId', 'conversation-1'))
          .contactFp,
        'alice',
      );
      assert.equal(
        (await DB.getAllByIndex('messages', 'contactFp', 'alice')).length,
        1,
      );
      await assert.rejects(Vault.unlock('a wrong password while unlocked'));
      assert.equal(Vault.isUnlocked(), false);
      await Vault.unlock(passphrase);
    },
  );

  await t.test(
    'typed array serializer safely roundtrips views and tag-like objects',
    async () => {
      const original = {
        ...contact('typed'),
        extras: {
          Uint8Array: ['object', [['__proto__', ['p', 'test']]]],
          signed: new Int16Array([-1, 257]),
          float: new Float64Array([Math.PI]),
          view: new DataView(new Uint8Array([1, 4]).buffer),
          big: new BigUint64Array([9n]),
          empty: undefined,
          bytes: new Uint8Array([0, 7, 9, 0]).subarray(1, 3),
        },
      };
      await DB.put('contacts', original);
      Vault.lock();
      await Vault.unlock(passphrase);
      assert.deepEqual(await DB.get('contacts', 'typed'), original);
    },
  );

  await t.test(
    'tampered ciphertext, primary keys, indices and cross-store copies fail closed',
    async () => {
      const saved = await raw('messages', (objectStore) =>
        objectStore.get('message-1'),
      );
      const tampered = structuredClone(saved);
      tampered.ciphertext[0] ^= 1;
      await raw(
        'messages',
        (objectStore) => objectStore.put(tampered),
        'readwrite',
      );
      await assert.rejects(DB.get('messages', 'message-1'));
      await raw(
        'messages',
        (objectStore) => objectStore.put({ ...saved, id: 'relocated' }),
        'readwrite',
      );
      await assert.rejects(DB.get('messages', 'relocated'));
      await raw(
        'messages',
        (objectStore) =>
          objectStore.put({ ...saved, contactFp: 'different-owner' }),
        'readwrite',
      );
      await assert.rejects(
        DB.getAllByIndex('messages', 'contactFp', 'different-owner'),
      );
      await raw(
        'messages',
        (objectStore) => objectStore.put(saved),
        'readwrite',
      );
      await DB.delete('messages', 'relocated');
      const storedIdentity = await raw('identity', (objectStore) =>
        objectStore.get('me'),
      );
      await raw(
        'replays',
        (objectStore) => objectStore.put(storedIdentity),
        'readwrite',
      );
      await assert.rejects(DB.get('replays', 'me'));
      await DB.delete('replays', 'me');
    },
  );

  await t.test(
    'batch failure rolls back all writes and rejects only after abort',
    async () => {
      const previous = IDBObjectStore.prototype.put;
      IDBObjectStore.prototype.put = function (...args) {
        if (this.name === 'messages') throw new Error('injected write failure');
        return previous.apply(this, args);
      };
      try {
        await assert.rejects(
          DB.putMany([
            ['contacts', contact('rolled-back')],
            ['messages', message('batch-fail')],
          ]),
          /injected write failure/,
        );
      } finally {
        IDBObjectStore.prototype.put = previous;
      }
      assert.equal(await DB.get('contacts', 'rolled-back'), undefined);
      assert.equal(await DB.get('messages', 'batch-fail'), undefined);
      await DB.put('messages', message('durable'));
      Vault.lock();
      await Vault.unlock(passphrase);
      assert.deepEqual(await DB.get('messages', 'durable'), message('durable'));
    },
  );

  await t.test(
    'peer deletion removes every conversation and session, preserves replay tombstones',
    async () => {
      await DB.putMany([
        ['contacts', contact('bob')],
        ['sessions', session('bob', 'bob-conv')],
        ['messages', message('alice-old', 'alice', 'old-alice-conv')],
        ['messages', message('bob-only', 'bob', 'bob-conv')],
        ['replays', { id: 'alice-handshake', contactFp: 'alice' }],
      ]);
      await DB.deletePeer('alice', false);
      assert(await DB.get('contacts', 'alice'));
      assert.equal(await DB.get('sessions', 'alice'), undefined);
      assert.deepEqual(
        await DB.getAllByIndex('messages', 'contactFp', 'alice'),
        [],
      );
      assert(await DB.get('messages', 'bob-only'));
      assert.deepEqual(await DB.get('replays', 'alice-handshake'), {
        id: 'alice-handshake',
        contactFp: 'alice',
      });
      await DB.deletePeer('alice');
      assert.equal(await DB.get('contacts', 'alice'), undefined);
      await DB.deleteConversation('bob-conv');
      assert.equal(await DB.get('messages', 'bob-only'), undefined);
      assert(await DB.get('sessions', 'bob'));
    },
  );

  await t.test(
    'in-flight operations cannot resurrect keys or return plaintext after lock',
    async () => {
      const write = DB.put('messages', message('late-write'));
      Vault.lock();
      await assert.rejects(write, /locked/);
      await Vault.unlock(passphrase);
      assert.equal(await DB.get('messages', 'late-write'), undefined);
      const read = DB.get('identity', 'me');
      Vault.lock();
      await assert.rejects(read, /locked|aborted/);
      const unlock = Vault.unlock(passphrase);
      Vault.lock();
      await assert.rejects(unlock, /locked/);
      assert.equal(Vault.isUnlocked(), false);
      await Vault.unlock(passphrase);
    },
  );

  await t.test(
    'crypto that completes after lock cannot publish plaintext, commit or reinstall keys',
    async () => {
      for (const [method, operation] of [
        ['decrypt', () => DB.get('identity', 'me')],
        ['encrypt', () => DB.put('messages', message('crypto-late-write'))],
        ['deriveKey', () => Vault.unlock(passphrase)],
      ]) {
        const pause = pauseCrypto(method);
        const pending = operation();
        const rejected = assert.rejects(pending, /locked/);
        await pause.entered;
        Vault.lock();
        pause.release();
        await rejected;
        assert.equal(Vault.isUnlocked(), false);
        await Vault.unlock(passphrase);
      }
      assert.equal(await DB.get('messages', 'crypto-late-write'), undefined);
    },
  );

  await t.test(
    'peer deletion queued behind another tab never acts after its vault is locked',
    async () => {
      const release = await holdStateLock();
      const deletion = DB.deletePeer('bob');
      const rejected = assert.rejects(deletion, /locked/);
      Vault.lock();
      await release();
      await rejected;
      await Vault.unlock(passphrase);
      assert(await DB.get('contacts', 'bob'));
    },
  );

  await t.test(
    'metadata tampering is detected while unlocked and on reopening',
    async () => {
      const saved = await raw('meta', (objectStore) =>
        objectStore.get('vault'),
      );
      const tampered = structuredClone(saved);
      tampered.ciphertext[0] ^= 1;
      await raw(
        'meta',
        (objectStore) => objectStore.put(tampered),
        'readwrite',
      );
      await assert.rejects(
        DB.put('contacts', contact('bad-metadata')),
        /locked/,
      );
      assert.equal(await Vault.status(), 'locked');
      await assert.rejects(Vault.unlock(passphrase));
      await raw('meta', (objectStore) => objectStore.put(saved), 'readwrite');
      await Vault.unlock(passphrase);
    },
  );

  await t.test(
    'legacy data is listed without opening or importing it; only explicit deletion removes it',
    async () => {
      const open = indexedDB.open('ECP_DB', 1);
      open.onupgradeneeded = () =>
        open.result.createObjectStore('identity', { keyPath: 'id' });
      const legacy = await request(open);
      const tx = legacy.transaction('identity', 'readwrite');
      tx.objectStore('identity').put({
        id: 'legacy-only',
        privateKey: 'raw legacy secret',
      });
      await committed(tx);
      legacy.close();
      const originalOpen = indexedDB.open.bind(indexedDB);
      indexedDB.open = function (name, ...args) {
        assert.notEqual(
          name,
          'ECP_DB',
          'legacy database must never be opened by vault code',
        );
        return originalOpen(name, ...args);
      };
      try {
        assert.equal(await Vault.hasLegacyData(), true);
        Vault.lock();
        await Vault.unlock(passphrase);
        assert.equal(await DB.get('identity', 'legacy-only'), undefined);
        await Vault.deleteLegacyData();
        assert.equal(await Vault.hasLegacyData(), false);
        assert(await DB.get('identity', 'me'));
      } finally {
        indexedDB.open = originalOpen;
      }
    },
  );

  await t.test(
    'destroy invalidates pending unlocks, removes data and allows a clean vault',
    async () => {
      Vault.lock();
      const unlock = Vault.unlock(passphrase);
      const destruction = Vault.destroy();
      await assert.rejects(unlock, /locked/);
      await destruction;
      assert.equal(Vault.isUnlocked(), false);
      assert(
        !(await indexedDB.databases()).some((db) => db.name === databaseName),
      );
      assert.equal(await Vault.status(), 'new');
      await Vault.create('a different secure passphrase');
      assert.equal((await DB.getAll('identity')).length, 1);
      assert.equal((await DB.get('identity', 'local')).id, 'local');
      for (const store of stores.filter((name) => name !== 'identity'))
        assert.deepEqual(await DB.getAll(store), []);
      // Simulate another tab deleting the database without using BroadcastChannel.
      await request(indexedDB.deleteDatabase(databaseName));
      assert.equal(Vault.isUnlocked(), false);
      await assert.rejects(DB.getAll('identity'), /locked/);
      assert.equal(await Vault.status(), 'new');
      const release = await holdStateLock();
      const creation = Vault.create(passphrase);
      const rejected = assert.rejects(creation, /locked/);
      Vault.lock();
      await release();
      await rejected;
      assert.equal(Vault.isUnlocked(), false);
      assert.equal(await Vault.status(), 'new');
      await Vault.destroy();
    },
  );
});
