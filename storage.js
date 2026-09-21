import { withStateLock } from './locks.js';
const DATABASE = 'ECP_SECURE_DB_v2';
const LEGACY_DATABASE = 'ECP_DB';
const DATABASE_VERSION = 1;
const SCHEMA = 2;
const ITERATIONS = 600_000;
const DATA_STORES = [
    'identity',
    'contacts',
    'sessions',
    'messages',
    'replays',
];
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
let database;
let opening;
let destroying;
let key;
let vaultId;
let metadataStamp;
let epoch = 0;
const activeTransactions = new Set();
const channel = typeof BroadcastChannel === 'undefined'
    ? undefined
    : new BroadcastChannel('ecp-vault-v2');
channel?.unref?.();
channel?.addEventListener('message', (event) => {
    if (event.data?.type === 'lock' || event.data?.type === 'destroy')
        invalidate();
});
function invalidate() {
    epoch++;
    key = undefined;
    vaultId = undefined;
    metadataStamp = undefined;
    for (const tx of activeTransactions) {
        try {
            tx.abort();
        }
        catch {
        }
    }
    database?.close();
    database = undefined;
    if (typeof globalThis.dispatchEvent === 'function')
        globalThis.dispatchEvent(new Event('ecp-vault-locked'));
}
function locked() {
    return new Error('Vault is locked or its state changed');
}
function ensureEpoch(expected) {
    if (epoch !== expected)
        throw locked();
}
function snapshot() {
    if (!key || !vaultId || !metadataStamp)
        throw locked();
    return { key, epoch, vaultId, metadataStamp };
}
function ensureActive(state) {
    ensureEpoch(state.epoch);
    if (key !== state.key || vaultId !== state.vaultId)
        throw locked();
}
function cryptoApi() {
    if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
        throw new Error('Secure WebCrypto is required');
    }
    return globalThis.crypto;
}
function random(length) {
    return cryptoApi().getRandomValues(new Uint8Array(length));
}
function bytes(value, length) {
    return (value instanceof Uint8Array &&
        (length === undefined || value.length === length));
}
function textId(value) {
    return typeof value === 'string' && value.length > 0;
}
function validateMetadata(value) {
    const m = value;
    if (!m ||
        m.id !== 'vault' ||
        m.schema !== SCHEMA ||
        !bytes(m.salt, 16) ||
        m.iterations !== ITERATIONS ||
        !/^[0-9a-f]{32}$/.test(m.vaultId) ||
        !bytes(m.iv, 12) ||
        !bytes(m.ciphertext) ||
        m.ciphertext.length < 16 ||
        Object.keys(m).sort().join(',') !==
            'ciphertext,id,iterations,iv,salt,schema,vaultId') {
        throw new Error('Invalid vault metadata; refusing to reset existing data');
    }
}
function validateSchema(db) {
    const expected = [...DATA_STORES, 'meta'].sort().join(',');
    if (Array.from(db.objectStoreNames).sort().join(',') !== expected)
        throw new Error('Invalid vault database schema');
    const tx = db.transaction([...DATA_STORES, 'meta'], 'readonly');
    for (const name of [...DATA_STORES, 'meta']) {
        const store = tx.objectStore(name);
        const expectedKey = name === 'contacts'
            ? 'fingerprint'
            : name === 'sessions'
                ? 'contactFp'
                : 'id';
        const expectedIndices = name === 'sessions'
            ? ['conversationId']
            : name === 'messages'
                ? ['contactFp', 'conversationId']
                : [];
        if (store.keyPath !== expectedKey ||
            store.autoIncrement ||
            Array.from(store.indexNames).sort().join(',') !==
                expectedIndices.join(',')) {
            throw new Error('Invalid vault database schema');
        }
        for (const name of expectedIndices) {
            const index = store.index(name);
            if (index.keyPath !== name || index.unique || index.multiEntry)
                throw new Error('Invalid vault database index');
        }
    }
}
function openDatabase() {
    if (database)
        return Promise.resolve(database);
    if (opening)
        return opening;
    const expectedEpoch = epoch;
    const pending = new Promise((resolve, reject) => {
        let failed = false;
        const req = indexedDB.open(DATABASE, DATABASE_VERSION);
        req.onupgradeneeded = (event) => {
            if (failed || epoch !== expectedEpoch || event.oldVersion !== 0) {
                req.transaction.abort();
                return;
            }
            const db = req.result;
            if (failed) {
                db.close();
                return;
            }
            db.createObjectStore('meta', { keyPath: 'id' });
            db.createObjectStore('identity', { keyPath: 'id' });
            db.createObjectStore('contacts', { keyPath: 'fingerprint' });
            db.createObjectStore('sessions', { keyPath: 'contactFp' }).createIndex('conversationId', 'conversationId');
            const messages = db.createObjectStore('messages', { keyPath: 'id' });
            messages.createIndex('conversationId', 'conversationId');
            messages.createIndex('contactFp', 'contactFp');
            db.createObjectStore('replays', { keyPath: 'id' });
        };
        req.onsuccess = () => {
            const db = req.result;
            try {
                ensureEpoch(expectedEpoch);
                validateSchema(db);
            }
            catch (error) {
                db.close();
                reject(error);
                return;
            }
            database = db;
            db.onversionchange = () => {
                db.close();
                invalidate();
            };
            db.onclose = () => {
                if (database === db)
                    invalidate();
            };
            resolve(db);
        };
        req.onerror = () => {
            failed = true;
            reject(epoch !== expectedEpoch
                ? locked()
                : (req.error ?? new Error('Cannot open vault')));
        };
        req.onblocked = () => {
            failed = true;
            reject(new Error('Vault database is blocked by another tab'));
        };
    });
    opening = pending;
    void pending
        .finally(() => {
        if (opening === pending)
            opening = undefined;
    })
        .catch(() => { });
    return pending;
}
function request(req) {
    return new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('Vault request failed'));
    });
}
function completion(tx, state) {
    activeTransactions.add(tx);
    return new Promise((resolve, reject) => {
        tx.oncomplete = () => {
            activeTransactions.delete(tx);
            try {
                if (state)
                    ensureActive(state);
                resolve();
            }
            catch (error) {
                reject(error);
            }
        };
        tx.onabort = () => {
            activeTransactions.delete(tx);
            reject(tx.error ?? new Error('Vault transaction aborted'));
        };
        tx.onerror = () => {
        };
    });
}
async function readMetadata() {
    const before = epoch;
    const db = await openDatabase();
    ensureEpoch(before);
    const tx = db.transaction(['meta', ...DATA_STORES], 'readonly');
    const done = completion(tx);
    const reads = [
        request(tx.objectStore('meta').getAll()),
        ...DATA_STORES.map((name) => request(tx.objectStore(name).count())),
    ];
    const [records, ...counts] = (await Promise.all([...reads, done]).then((values) => values.slice(0, -1)));
    ensureEpoch(before);
    if (records.length === 0) {
        if (counts.some((count) => count !== 0))
            throw new Error('Vault metadata missing; refusing to reset existing data');
        return undefined;
    }
    if (records.length !== 1)
        throw new Error('Invalid vault metadata records');
    validateMetadata(records[0]);
    return records[0];
}
function checkPassphrase(passphrase) {
    if (typeof passphrase !== 'string' || [...passphrase].length < 12)
        throw new Error('Use a passphrase of at least 12 characters');
}
async function derive(passphrase, salt) {
    checkPassphrase(passphrase);
    const raw = encoder.encode(passphrase);
    try {
        const material = await cryptoApi().subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
        return await cryptoApi().subtle.deriveKey({
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt: salt,
            iterations: ITERATIONS,
        }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }
    finally {
        raw.fill(0);
    }
}
function metaAAD(m) {
    return encoder.encode(JSON.stringify([
        DATABASE,
        SCHEMA,
        'meta',
        'vault',
        m.vaultId,
        Array.from(m.salt),
        m.iterations,
    ]));
}
function stamp(m) {
    return JSON.stringify([
        m.id,
        m.schema,
        m.vaultId,
        m.iterations,
        base64(m.salt),
        base64(m.iv),
        base64(m.ciphertext),
    ]);
}
function base64(value) {
    let result = '';
    for (let i = 0; i < value.length; i += 0x8000)
        result += String.fromCharCode(...value.subarray(i, i + 0x8000));
    return btoa(result);
}
function encode(value) {
    if (value === undefined)
        return ['u'];
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return ['p', value];
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new Error('Non-finite vault number');
        return ['p', value];
    }
    if (typeof value === 'bigint')
        return ['bigint', String(value)];
    if (value instanceof ArrayBuffer)
        return ['ArrayBuffer', base64(new Uint8Array(value))];
    if (ArrayBuffer.isView(value))
        return [
            value.constructor.name,
            base64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)),
        ];
    if (Array.isArray(value))
        return ['array', value.map(encode)];
    if (typeof value === 'object' &&
        Object.getPrototypeOf(value) === Object.prototype) {
        return ['object', Object.entries(value).map(([k, v]) => [k, encode(v)])];
    }
    throw new Error('Unsupported vault value');
}
function decode(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > 2)
        throw new Error('Invalid vault payload');
    const [tag, data] = value;
    if (tag === 'u')
        return undefined;
    if (tag === 'p') {
        if (data === null ||
            typeof data === 'string' ||
            typeof data === 'boolean' ||
            (typeof data === 'number' && Number.isFinite(data)))
            return data;
        throw new Error('Invalid primitive');
    }
    if (tag === 'bigint' && typeof data === 'string')
        return BigInt(data);
    if (tag === 'array' && Array.isArray(data))
        return data.map((item) => decode(item));
    if (tag === 'object' && Array.isArray(data)) {
        const result = {};
        for (const pair of data) {
            if (!Array.isArray(pair) ||
                pair.length !== 2 ||
                typeof pair[0] !== 'string' ||
                Object.hasOwn(result, pair[0]))
                throw new Error('Invalid object');
            Object.defineProperty(result, pair[0], {
                value: decode(pair[1]),
                enumerable: true,
                writable: true,
                configurable: true,
            });
        }
        return result;
    }
    const constructors = {
        ArrayBuffer: (b) => b,
        DataView: (b) => new DataView(b),
        Uint8Array: (b) => new Uint8Array(b),
        Uint8ClampedArray: (b) => new Uint8ClampedArray(b),
        Int8Array: (b) => new Int8Array(b),
        Int16Array: (b) => new Int16Array(b),
        Uint16Array: (b) => new Uint16Array(b),
        Int32Array: (b) => new Int32Array(b),
        Uint32Array: (b) => new Uint32Array(b),
        Float32Array: (b) => new Float32Array(b),
        Float64Array: (b) => new Float64Array(b),
        BigInt64Array: (b) => new BigInt64Array(b),
        BigUint64Array: (b) => new BigUint64Array(b),
    };
    if (Object.hasOwn(constructors, tag) && typeof data === 'string') {
        const raw = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
        return constructors[tag](raw.buffer);
    }
    throw new Error('Invalid vault value tag');
}
function header(store, item) {
    const value = item;
    const fields = store === 'contacts'
        ? ['fingerprint']
        : store === 'sessions'
            ? ['contactFp', 'conversationId']
            : store === 'messages'
                ? ['id', 'conversationId', 'contactFp']
                : ['id'];
    const result = {};
    for (const field of fields) {
        if (!textId(value[field]))
            throw new Error(`Missing ${store}.${field}`);
        result[field] = value[field];
    }
    return result;
}
function aad(store, fields, id) {
    return encoder.encode(JSON.stringify([
        DATABASE,
        SCHEMA,
        id,
        store,
        fields.id ?? null,
        fields.fingerprint ?? null,
        fields.contactFp ?? null,
        fields.conversationId ?? null,
    ]));
}
async function seal(store, item, state) {
    ensureActive(state);
    const fields = header(store, item);
    const iv = random(12);
    const plaintext = encoder.encode(JSON.stringify(encode(item)));
    try {
        const ciphertext = new Uint8Array(await cryptoApi().subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
            additionalData: aad(store, fields, state.vaultId),
        }, state.key, plaintext));
        ensureActive(state);
        return { schema: SCHEMA, ...fields, iv, ciphertext };
    }
    finally {
        plaintext.fill(0);
    }
}
async function unseal(store, envelope, state) {
    ensureActive(state);
    if (!envelope ||
        envelope.schema !== SCHEMA ||
        !bytes(envelope.iv, 12) ||
        !bytes(envelope.ciphertext) ||
        envelope.ciphertext.length < 16)
        throw new Error('Invalid encrypted vault record');
    const fields = header(store, envelope);
    const allowedKeys = ['schema', 'iv', 'ciphertext', ...Object.keys(fields)]
        .sort()
        .join(',');
    if (Object.keys(envelope).sort().join(',') !== allowedKeys)
        throw new Error('Unexpected encrypted vault fields');
    let plaintext;
    try {
        plaintext = new Uint8Array(await cryptoApi().subtle.decrypt({
            name: 'AES-GCM',
            iv: envelope.iv,
            additionalData: aad(store, fields, state.vaultId),
        }, state.key, envelope.ciphertext));
        ensureActive(state);
        const item = decode(JSON.parse(decoder.decode(plaintext)));
        if (JSON.stringify(header(store, item)) !== JSON.stringify(fields))
            throw new Error('Vault record key mismatch');
        ensureActive(state);
        return item;
    }
    finally {
        plaintext?.fill(0);
    }
}
async function transaction(stores, mode, state, action) {
    const db = await openDatabase();
    ensureActive(state);
    const tx = db.transaction([...new Set(['meta', ...stores])], mode);
    const done = completion(tx, state);
    try {
        const metadata = await request(tx.objectStore('meta').get('vault'));
        validateMetadata(metadata);
        if (metadata.vaultId !== state.vaultId ||
            stamp(metadata) !== state.metadataStamp)
            throw locked();
        ensureActive(state);
        const result = await action(tx);
        await done;
        ensureActive(state);
        return result;
    }
    catch (error) {
        try {
            tx.abort();
        }
        catch {
        }
        await done.catch(() => { });
        throw error;
    }
}
async function read(store, query) {
    const state = snapshot();
    const result = await transaction([store], 'readonly', state, (tx) => request(query(tx.objectStore(store))));
    if (result === undefined) {
        ensureActive(state);
        return undefined;
    }
    return unseal(store, result, state);
}
async function readAll(store, query) {
    const state = snapshot();
    const results = await transaction([store], 'readonly', state, (tx) => request(query(tx.objectStore(store))));
    const values = await Promise.all(results.map((item) => unseal(store, item, state)));
    ensureActive(state);
    return values;
}
function deleteCursor(index, match) {
    return new Promise((resolve, reject) => {
        const req = index.openCursor(IDBKeyRange.only(match));
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
            const cursor = req.result;
            if (!cursor) {
                resolve();
                return;
            }
            cursor.delete();
            cursor.continue();
        };
    });
}
export const DB = {
    get: (store, id) => read(store, (objectStore) => objectStore.get(id)),
    getAll: (store) => readAll(store, (objectStore) => objectStore.getAll()),
    getByIndex: (store, index, value) => read(store, (objectStore) => objectStore.index(index).get(value)),
    getAllByIndex: (store, index, value) => readAll(store, (objectStore) => objectStore.index(index).getAll(value)),
    put: async (store, item) => {
        await DB.putMany([[store, item]]);
    },
    putMany: async (entries) => {
        const state = snapshot();
        const encrypted = await Promise.all(entries.map(async ([store, item]) => [store, await seal(store, item, state)]));
        ensureActive(state);
        if (!entries.length)
            return;
        await transaction(encrypted.map(([store]) => store), 'readwrite', state, (tx) => {
            for (const [store, envelope] of encrypted)
                tx.objectStore(store).put(envelope);
        });
    },
    delete: async (store, id) => {
        const state = snapshot();
        await transaction([store], 'readwrite', state, (tx) => {
            tx.objectStore(store).delete(id);
        });
    },
    deleteConversation: async (conversationId) => {
        const state = snapshot();
        await withStateLock(async () => {
            ensureActive(state);
            await transaction(['messages'], 'readwrite', state, (tx) => deleteCursor(tx.objectStore('messages').index('conversationId'), conversationId));
        });
    },
    deletePeer: async (contactFp, removeContact = true) => {
        const state = snapshot();
        await withStateLock(async () => {
            ensureActive(state);
            await transaction(['contacts', 'sessions', 'messages'], 'readwrite', state, async (tx) => {
                tx.objectStore('sessions').delete(contactFp);
                if (removeContact)
                    tx.objectStore('contacts').delete(contactFp);
                await deleteCursor(tx.objectStore('messages').index('contactFp'), contactFp);
            });
        });
    },
};
export const Vault = {
    status: async () => {
        await destroying;
        const metadata = await readMetadata();
        if (!metadata) {
            if (key)
                invalidate();
            return 'new';
        }
        if (key &&
            vaultId === metadata.vaultId &&
            metadataStamp === stamp(metadata))
            return 'unlocked';
        if (key)
            invalidate();
        return 'locked';
    },
    create: async (passphrase) => {
        if (destroying)
            throw locked();
        checkPassphrase(passphrase);
        const before = epoch;
        await withStateLock(async () => {
            ensureEpoch(before);
            if (await readMetadata())
                throw new Error('Vault already exists');
            ensureEpoch(before);
            const salt = random(16);
            const newKey = await derive(passphrase, salt);
            ensureEpoch(before);
            const metadata = {
                id: 'vault',
                schema: SCHEMA,
                salt,
                iterations: ITERATIONS,
                vaultId: Array.from(random(16), (b) => b.toString(16).padStart(2, '0')).join(''),
                iv: random(12),
                ciphertext: new Uint8Array(),
            };
            metadata.ciphertext = new Uint8Array(await cryptoApi().subtle.encrypt({
                name: 'AES-GCM',
                iv: metadata.iv,
                additionalData: metaAAD(metadata),
            }, newKey, encoder.encode('ecp-password-vault-v2')));
            ensureEpoch(before);
            const db = await openDatabase();
            ensureEpoch(before);
            const tx = db.transaction('meta', 'readwrite');
            const done = completion(tx);
            tx.objectStore('meta').add(metadata);
            await done;
            ensureEpoch(before);
            key = newKey;
            vaultId = metadata.vaultId;
            metadataStamp = stamp(metadata);
        });
    },
    unlock: async (passphrase) => {
        invalidate();
        if (destroying)
            throw locked();
        checkPassphrase(passphrase);
        const before = epoch;
        const metadata = await readMetadata();
        if (!metadata)
            throw new Error('Create a vault first');
        ensureEpoch(before);
        const newKey = await derive(passphrase, metadata.salt);
        ensureEpoch(before);
        let plaintext;
        try {
            plaintext = new Uint8Array(await cryptoApi().subtle.decrypt({
                name: 'AES-GCM',
                iv: metadata.iv,
                additionalData: metaAAD(metadata),
            }, newKey, metadata.ciphertext));
            if (decoder.decode(plaintext) !== 'ecp-password-vault-v2')
                throw new Error('Invalid vault verifier');
            ensureEpoch(before);
            const current = await readMetadata();
            ensureEpoch(before);
            if (!current || stamp(current) !== stamp(metadata))
                throw locked();
            key = newKey;
            vaultId = metadata.vaultId;
            metadataStamp = stamp(metadata);
        }
        finally {
            plaintext?.fill(0);
        }
    },
    lock: () => {
        invalidate();
        channel?.postMessage({ type: 'lock' });
    },
    isUnlocked: () => Boolean(key && vaultId),
    destroy: async () => {
        if (destroying)
            return destroying;
        let finish;
        let fail;
        const pending = new Promise((resolve, reject) => {
            finish = resolve;
            fail = reject;
        });
        destroying = pending;
        invalidate();
        channel?.postMessage({ type: 'destroy' });
        void withStateLock(async () => {
            await opening?.catch(() => { });
            invalidate();
            await deleteDatabase(DATABASE);
        }).then(() => {
            destroying = undefined;
            finish();
        }, (error) => {
            destroying = undefined;
            fail(error);
        });
        return pending;
    },
    hasLegacyData: async () => {
        if (typeof indexedDB.databases !== 'function')
            throw new Error('Cannot inspect legacy storage safely in this browser');
        return (await indexedDB.databases()).some((db) => db.name === LEGACY_DATABASE);
    },
    deleteLegacyData: () => withStateLock(() => deleteDatabase(LEGACY_DATABASE)),
};
function deleteDatabase(name) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase(name);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error ?? new Error('Cannot delete database'));
        req.onblocked = () => reject(new Error('Close other ECP tabs before deleting this database'));
    });
}
//# sourceMappingURL=storage.js.map