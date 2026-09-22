import { Config } from './config.js';
import { concatBytes, sha256, encodeBase64URL } from './crypto.js';
import { withNamedLock } from './locks.js';
import { DB, Vault } from './storage.js';
import type { Identity } from './types.js';
import { validateLocalIdentity } from './identity-material.js';

export const getLocalIdentity = async () => {
  const assertAccess = Vault.captureAccess();
  return withNamedLock('identity', async () => {
    assertAccess();
    const id = await DB.get('identity', 'local');
    assertAccess();
    validateLocalIdentity(id);
    return id;
  });
};

export const serializeIdentityPublic = (id: Identity) =>
  concatBytes(
    new Uint8Array([Config.IDENTITY_VERSION]),
    id.ecPk,
    id.dsaPk,
    id.dhPk,
    id.kemPk,
  );

export const parseIdentityPublic = (bytes: Uint8Array) => {
  if (bytes.length !== 4225) throw new Error('Malformed identity packet.');
  if (bytes[0] !== Config.IDENTITY_VERSION)
    throw new Error('Unsupported identity version.');
  return {
    ecPk: bytes.slice(1, 33),
    dsaPk: bytes.slice(33, 2625),
    dhPk: bytes.slice(2625, 2657),
    kemPk: bytes.slice(2657, 4225),
  };
};

export const calculateFingerprint = (identityBytes: Uint8Array) => {
  const idPub = parseIdentityPublic(identityBytes);
  return encodeBase64URL(
    sha256(
      concatBytes(
        new TextEncoder().encode('ECP-ID-v2'),
        idPub.ecPk,
        idPub.dsaPk,
        idPub.dhPk,
        idPub.kemPk,
      ),
    ),
  );
};

export const getLocalFingerprint = async () =>
  calculateFingerprint(serializeIdentityPublic(await getLocalIdentity()));
