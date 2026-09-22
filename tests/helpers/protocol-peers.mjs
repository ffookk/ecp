import {
  mkdtemp,
  readFile,
  writeFile,
  mkdir,
  symlink,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { stripTypeScriptTypes } from 'node:module';

// Only storage and the origin lock are adapted. The full protocol, codec,
// identity generation and Noble cryptography are the production source.
const storageAdapter = `
const stores = Object.fromEntries(['identity','contacts','sessions','messages','replays'].map(s => [s, new Map()]));
const keyOf = (s, v) => s === 'contacts' ? v.fingerprint : s === 'sessions' ? v.contactFp : v.id;
const clone = v => v === undefined ? undefined : structuredClone(v);
let fail = false;
let epoch = 0;
let unlocked = true;
export const Vault = {
  captureAccess() {
    const before = epoch;
    const check = () => {
      if (!unlocked || before !== epoch) throw new Error('Vault is locked or changed');
    };
    check();
    return check;
  },
  lock() { unlocked = false; epoch++; },
  unlock() { unlocked = true; epoch++; },
};
export const DB = {
  async get(s, k) { await Promise.resolve(); return clone(stores[s].get(k)); },
  async getAll(s) { return [...stores[s].values()].map(clone); },
  async getByIndex(s, field, value) { return clone([...stores[s].values()].find(v => v[field] === value)); },
  async put(s, v) { return this.putMany([[s,v]]); },
  async putMany(entries) {
    const staged = entries.map(([s,v]) => [s, clone(v)]);
    await Promise.resolve();
    if (fail) { fail = false; throw new Error('Injected transaction abort'); }
    for (const [s,v] of staged) stores[s].set(keyOf(s,v), v);
  },
  async delete(s, k) { stores[s].delete(k); },
  failNextCommit() { fail = true; },
  snapshot() { return clone(Object.fromEntries(Object.entries(stores).map(([s,m]) => [s,[...m.entries()]]))); },
  restore(snapshot) {
    for (const [s, entries] of Object.entries(clone(snapshot))) {
      stores[s].clear();
      for (const [key, value] of entries) stores[s].set(key, value);
    }
  },
};
`;

const lockAdapter = `
const queues = new Map();
export function withNamedLock(name, fn) {
  const result = (queues.get(name) ?? Promise.resolve()).then(fn);
  queues.set(name, result.catch(() => {}));
  return result;
}
export const withStateLock = fn => withNamedLock('state', fn);
`;

export async function createProtocolLab(t) {
  const root = resolve(import.meta.dirname, '../..');
  const sandbox = await mkdtemp(join(tmpdir(), 'ecp-protocol-'));
  t.after(() => rm(sandbox, { recursive: true, force: true }));
  await writeFile(join(sandbox, 'package.json'), '{"type":"module"}');
  await symlink(
    join(root, 'node_modules'),
    join(sandbox, 'node_modules'),
    'dir',
  );
  let count = 0;
  async function peer(snapshot) {
    const directory = join(sandbox, `peer-${count++}`);
    await mkdir(directory);
    for (const name of [
      'config',
      'crypto',
      'codec',
      'identity',
      'identity-material',
      'mutex',
      'ratchet',
    ]) {
      const source = await readFile(join(root, 'src', `${name}.ts`), 'utf8');
      await writeFile(
        join(directory, `${name}.js`),
        stripTypeScriptTypes(source),
      );
    }
    await writeFile(join(directory, 'storage.js'), storageAdapter);
    await writeFile(join(directory, 'locks.js'), lockAdapter);
    const load = (name) =>
      import(pathToFileURL(join(directory, `${name}.js`)).href);
    const [protocol, identity, cryptography, storage, locks, codec, config] =
      await Promise.all(
        [
          'ratchet',
          'identity',
          'crypto',
          'storage',
          'locks',
          'codec',
          'config',
        ].map(load),
      );
    if (snapshot) storage.DB.restore(snapshot);
    else {
      const { createIdentityMaterial } = await load('identity-material');
      await storage.DB.put('identity', createIdentityMaterial());
    }
    const local = await identity.getLocalIdentity();
    const publicBytes = identity.serializeIdentityPublic(local);
    return {
      ...protocol,
      ...storage,
      ...locks,
      identity,
      cryptography,
      codec,
      Config: config.Config,
      local,
      publicBytes,
      fingerprint: identity.calculateFingerprint(publicBytes),
      bundle: cryptography.encodeBase64URL(publicBytes),
    };
  }
  async function link(a, b, verified = true) {
    await a.DB.put('contacts', {
      fingerprint: b.fingerprint,
      bundle: b.bundle,
      name: 'Test peer',
      verified,
      saveHistory: true,
      archived: false,
      lastReadTimestamp: 0,
    });
  }
  async function pair(establish = true) {
    const [a, b] = await Promise.all([peer(), peer()]);
    await Promise.all([link(a, b), link(b, a)]);
    if (!establish) return { a, b };
    const init = await a.CreateInit(b.fingerprint);
    const response = await b.ProcessInit(init.packet);
    await a.ProcessResp(response.respPacket);
    return { a, b, init, response };
  }
  return { peer, link, pair };
}

export function changed(packet, mutate) {
  const copy = packet.slice();
  mutate(copy, new DataView(copy.buffer, copy.byteOffset, copy.byteLength));
  return copy;
}

export const sequence = (packet) =>
  new DataView(packet.buffer, packet.byteOffset, packet.byteLength).getUint32(
    3200,
  );
