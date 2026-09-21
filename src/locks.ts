import { Config } from './config.js';

// No per-tab fallback: a weaker lock would permit ratchet key reuse.
export async function withNamedLock<T>(
  name: string,
  operation: () => Promise<T>,
): Promise<T> {
  if (!globalThis.navigator?.locks)
    throw new Error('This browser must support Web Locks in a secure context.');
  return navigator.locks.request(
    `${Config.STORAGE_DB_NAME}:${name}`,
    operation,
  );
}

export const withStateLock = <T>(operation: () => Promise<T>) =>
  withNamedLock('state', operation);
