import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { indexedDB, IDBKeyRange } from 'fake-indexeddb';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
});
Object.assign(globalThis, { indexedDB, IDBKeyRange });
const events = new EventTarget();
Object.defineProperty(globalThis, 'dispatchEvent', {
  configurable: true,
  value: events.dispatchEvent.bind(events),
});
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

const passphrase = 'synthetic-inactivity-test-passphrase';
const databaseName = 'ECP_SECURE_DB_v2';
const timeout = 300_000;
const expired = /locked|expired|changed/i;
const peer = {
  fingerprint: 'synthetic-inactivity-peer',
  bundle: 'synthetic-public-bundle',
  name: 'Synthetic inactivity peer',
  verified: true,
  archived: false,
  lastReadTimestamp: 0,
};
const request = (req) =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
async function rawContact() {
  const database = await request(indexedDB.open(databaseName, 1));
  try {
    const tx = database.transaction('contacts', 'readonly');
    const done = new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onabort = () => reject(tx.error ?? new Error('aborted'));
    });
    const value = await request(
      tx.objectStore('contacts').get(peer.fingerprint),
    );
    await done;
    return value;
  } finally {
    database.close();
  }
}
async function holdStateLock() {
  let release, entered;
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  const held = navigator.locks.request(`${databaseName}:state`, () => {
    entered();
    return new Promise((resolve) => {
      release = resolve;
    });
  });
  await started;
  return async () => {
    release();
    await held;
  };
}
function pauseCrypto(t, method) {
  const original = webcrypto.subtle[method];
  let resume, entered;
  const waiting = new Promise((resolve) => {
    resume = resolve;
  });
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  t.mock.method(webcrypto.subtle, method, async function (...args) {
    const result = await original.apply(this, args);
    entered();
    await waiting;
    return result;
  });
  return { started, release: resume };
}

test('vault inactivity is enforced by storage even when browser timers are delayed', async (t) => {
  // Move the clocks without running timeout callbacks. Real Web Crypto and
  // IndexedDB operations therefore exercise their own elapsed-time checks.
  const clock = {
    wall: 1_800_000_000_000,
    monotonic: 100_000,
    reset() {
      this.wall = 1_800_000_000_000;
      this.monotonic = 100_000;
    },
    advance(milliseconds) {
      this.wall += milliseconds;
      this.monotonic += milliseconds;
    },
  };
  t.mock.method(Date, 'now', () => clock.wall);
  t.mock.method(performance, 'now', () => clock.monotonic);
  async function freshUnlock() {
    Vault.lock();
    clock.reset();
    await Vault.unlock(passphrase);
  }
  t.after(async () => {
    Vault.lock();
    clock.reset();
    await Vault.destroy();
  });
  await Vault.destroy();

  await t.test(
    'creation starts the deadline without any UI activity',
    async () => {
      await Vault.create(passphrase);
      await DB.put('contacts', peer);
      assert.equal(Vault.isUnlocked(), true);
      clock.advance(timeout);
      assert.throws(() => Vault.captureAccess(), expired);
      assert.equal(Vault.isUnlocked(), false);
      assert.equal(await Vault.status(), 'locked');
      assert((await rawContact()).ciphertext instanceof Uint8Array);
    },
  );

  await t.test(
    'unlock, status and access checks enforce the exact deadline',
    async () => {
      for (const check of [
        () => assert.equal(Vault.isUnlocked(), false),
        async () => assert.equal(await Vault.status(), 'locked'),
        () => assert.throws(() => Vault.captureAccess(), expired),
      ]) {
        await freshUnlock();
        clock.advance(timeout - 1);
        assert.equal(Vault.isUnlocked(), true);
        clock.advance(1);
        await check();
        assert.equal(Vault.isUnlocked(), false);
      }
    },
  );

  await t.test(
    'expired reads, writes and retained guards fail without changing ciphertext',
    async () => {
      const before = await rawContact();
      for (const operation of [
        () => DB.get('contacts', peer.fingerprint),
        () => DB.getAll('contacts'),
        () => DB.put('contacts', { ...peer, name: 'Must not be committed' }),
      ]) {
        await freshUnlock();
        clock.advance(timeout);
        await assert.rejects(operation(), expired);
        assert.deepEqual(await rawContact(), before);
      }
      await freshUnlock();
      const retained = Vault.captureAccess();
      clock.advance(timeout);
      assert.throws(retained, expired);
      await freshUnlock();
      assert.throws(retained, expired);
      assert.deepEqual(await DB.get('contacts', peer.fingerprint), peer);
    },
  );

  await t.test(
    'ordinary successful storage reads never renew the deadline',
    async () => {
      await freshUnlock();
      clock.advance(120_000);
      assert.deepEqual(await DB.get('contacts', peer.fingerprint), peer);
      clock.advance(120_000);
      assert.deepEqual(await DB.getAll('contacts'), [peer]);
      clock.advance(60_000);
      await assert.rejects(DB.get('contacts', peer.fingerprint), expired);
      assert.equal(Vault.isUnlocked(), false);
    },
  );

  await t.test(
    'activity before expiry renews a lease, but late activity cannot resurrect it',
    async () => {
      await freshUnlock();
      clock.advance(299_000);
      assert.equal(Vault.touchActivity(), true);
      clock.advance(2_000);
      assert.deepEqual(await DB.get('contacts', peer.fingerprint), peer);
      clock.advance(298_000);
      assert.equal(Vault.touchActivity(), false);
      assert.equal(Vault.isUnlocked(), false);
      clock.reset();
      assert.equal(Vault.touchActivity(), false);
      assert.throws(() => Vault.captureAccess(), expired);
      await freshUnlock();
      assert.equal(Vault.touchActivity(), true);
    },
  );

  for (const method of ['decrypt', 'encrypt']) {
    await t.test(
      `a pending ${method} cannot release plaintext or commit after expiry`,
      async (child) => {
        await freshUnlock();
        const before = await rawContact();
        const gate = pauseCrypto(child, method);
        const operation =
          method === 'decrypt'
            ? DB.get('contacts', peer.fingerprint)
            : DB.put('contacts', { ...peer, name: 'Late synthetic write' });
        const rejected = assert.rejects(operation, expired);
        try {
          await gate.started;
          clock.advance(timeout);
        } finally {
          gate.release();
        }
        await rejected;
        assert.equal(Vault.isUnlocked(), false);
        assert.deepEqual(await rawContact(), before);
      },
    );
  }

  await t.test(
    'an expired deletion queued on the state lock cannot delete data',
    async () => {
      await freshUnlock();
      const before = await rawContact();
      const release = await holdStateLock();
      const rejected = assert.rejects(DB.deletePeer(peer.fingerprint), expired);
      try {
        clock.advance(timeout);
      } finally {
        await release();
      }
      await rejected;
      assert.deepEqual(await rawContact(), before);
    },
  );

  await t.test(
    'unlocking again cannot authorize queued work from an expired lease',
    async () => {
      await freshUnlock();
      const before = await rawContact();
      const release = await holdStateLock();
      const rejected = assert.rejects(DB.deletePeer(peer.fingerprint), expired);
      try {
        clock.advance(timeout);
        assert.equal(Vault.isUnlocked(), false);
        clock.reset();
        await Vault.unlock(passphrase);
        assert.equal(Vault.isUnlocked(), true);
      } finally {
        await release();
      }
      await rejected;
      assert.deepEqual(await rawContact(), before);
      assert.deepEqual(await DB.get('contacts', peer.fingerprint), peer);
    },
  );

  await t.test('either clock can independently expire a lease', async () => {
    for (const name of ['wall', 'monotonic']) {
      await freshUnlock();
      clock[name] += timeout;
      await assert.rejects(DB.get('contacts', peer.fingerprint), expired);
      assert.equal(Vault.touchActivity(), false);
    }
  });

  await t.test(
    'a backwards jump after an observed read expires even above the lease baseline',
    async () => {
      for (const name of ['wall', 'monotonic']) {
        await freshUnlock();
        clock.advance(60_000);
        assert.deepEqual(await DB.get('contacts', peer.fingerprint), peer);
        clock[name] -= 1;
        assert.equal(Vault.touchActivity(), false);
        assert.equal(Vault.isUnlocked(), false);
      }
    },
  );

  await t.test(
    'backwards or nonfinite wall and monotonic readings fail closed',
    async () => {
      for (const name of ['wall', 'monotonic']) {
        for (const invalid of ['backwards', NaN, Infinity, -Infinity]) {
          await freshUnlock();
          clock[name] = invalid === 'backwards' ? clock[name] - 1 : invalid;
          assert.equal(Vault.touchActivity(), false);
          assert.equal(Vault.isUnlocked(), false);
          await assert.rejects(DB.get('contacts', peer.fingerprint), expired);
        }
      }
    },
  );

  await t.test(
    'the scheduled callback locks without a read and renewal cancels the old timer',
    async (child) => {
      Vault.lock();
      clock.reset();
      child.mock.timers.enable({ apis: ['setTimeout'] });
      let notifications = 0;
      const locked = () => notifications++;
      try {
        await Vault.unlock(passphrase);
        events.addEventListener('ecp-vault-locked', locked);
        clock.advance(299_000);
        child.mock.timers.tick(299_000);
        assert.equal(notifications, 0);
        assert.equal(Vault.touchActivity(), true);
        clock.advance(1_000);
        child.mock.timers.tick(1_000);
        assert.equal(
          notifications,
          0,
          'the original timeout must be cancelled',
        );
        clock.advance(299_000);
        child.mock.timers.tick(299_000);
        // Check notification before calling an API that could itself enforce expiry.
        assert.equal(notifications, 1);
        assert.equal(Vault.isUnlocked(), false);
        assert.equal(Vault.touchActivity(), false);
      } finally {
        events.removeEventListener('ecp-vault-locked', locked);
        Vault.lock();
        child.mock.timers.reset();
        clock.reset();
      }
    },
  );

  await t.test(
    'manual lock clears the old deadline before a fresh unlock',
    async (child) => {
      Vault.lock();
      clock.reset();
      child.mock.timers.enable({ apis: ['setTimeout'] });
      let notifications = 0;
      const locked = () => notifications++;
      try {
        await Vault.unlock(passphrase);
        clock.advance(100_000);
        child.mock.timers.tick(100_000);
        Vault.lock();
        clock.reset();
        await Vault.unlock(passphrase);
        events.addEventListener('ecp-vault-locked', locked);
        clock.advance(200_000);
        child.mock.timers.tick(200_000);
        assert.equal(notifications, 0);
        assert.equal(Vault.isUnlocked(), true);
        clock.advance(100_000);
        child.mock.timers.tick(100_000);
        assert.equal(notifications, 1);
        assert.equal(Vault.isUnlocked(), false);
      } finally {
        events.removeEventListener('ecp-vault-locked', locked);
        Vault.lock();
        child.mock.timers.reset();
        clock.reset();
      }
    },
  );
});
