import {
  keygenEd25519,
  keygenMLDSA87,
  keygenX25519,
  keygenMLKEM1024,
  concatBytes,
  sha256,
  encodeBase64URL,
} from './crypto.js';
import type { Identity } from './types.js';

const lengths = {
  ecSk: 32,
  ecPk: 32,
  dsaSk: 4896,
  dsaPk: 2592,
  dhSk: 32,
  dhPk: 32,
  kemSk: 3168,
  kemPk: 1568,
} as const;

export function validateLocalIdentity(
  value: unknown,
): asserts value is Identity {
  const id = value as Identity | undefined;
  if (
    !id ||
    id.id !== 'local' ||
    Object.keys(id).sort().join(',') !==
      ['id', ...Object.keys(lengths)].sort().join(',') ||
    Object.entries(lengths).some(([name, size]) => {
      const bytes = id[name as keyof typeof lengths];
      return !(bytes instanceof Uint8Array) || bytes.length !== size;
    })
  )
    throw new Error(
      'Vault identity is missing or corrupt; refusing to replace it.',
    );
}

// Only explicit vault initialization may call this storage-independent helper.
export function createIdentityMaterial(): Identity {
  const ec = keygenEd25519(),
    dsa = keygenMLDSA87();
  const dh = keygenX25519(),
    kem = keygenMLKEM1024();
  return {
    id: 'local',
    ecSk: ec.secretKey,
    ecPk: ec.publicKey,
    dsaSk: dsa.secretKey,
    dsaPk: dsa.publicKey,
    dhSk: dh.secretKey,
    dhPk: dh.publicKey,
    kemSk: kem.secretKey,
    kemPk: kem.publicKey,
  };
}

// This binding is stored only INSIDE the encrypted verifier. It binds all key
// material, not just public keys, and does not claim whole-database freshness.
export function identityBinding(id: Identity): string {
  validateLocalIdentity(id);
  const input = concatBytes(
    new TextEncoder().encode('ECP-VAULT-IDENTITY-v1'),
    ...Object.keys(lengths).map((name) => id[name as keyof typeof lengths]),
  );
  try {
    return encodeBase64URL(sha256(input));
  } finally {
    input.fill(0);
  }
}

export function clearIdentityMaterial(id: Identity): void {
  for (const name of Object.keys(lengths))
    id[name as keyof typeof lengths].fill(0);
}
