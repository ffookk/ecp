import { Config } from './config.js';
export async function withNamedLock(name, operation) {
    if (!globalThis.navigator?.locks)
        throw new Error('This browser must support Web Locks in a secure context.');
    return navigator.locks.request(`${Config.STORAGE_DB_NAME}:${name}`, operation);
}
export const withStateLock = (operation) => withNamedLock('state', operation);
//# sourceMappingURL=locks.js.map