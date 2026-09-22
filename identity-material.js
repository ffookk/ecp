import { keygenEd25519, keygenMLDSA87, keygenX25519, keygenMLKEM1024, concatBytes, sha256, encodeBase64URL, } from './crypto.js';
const lengths = {
    ecSk: 32,
    ecPk: 32,
    dsaSk: 4896,
    dsaPk: 2592,
    dhSk: 32,
    dhPk: 32,
    kemSk: 3168,
    kemPk: 1568,
};
export function validateLocalIdentity(value) {
    const id = value;
    if (!id ||
        id.id !== 'local' ||
        Object.keys(id).sort().join(',') !==
            ['id', ...Object.keys(lengths)].sort().join(',') ||
        Object.entries(lengths).some(([name, size]) => {
            const bytes = id[name];
            return !(bytes instanceof Uint8Array) || bytes.length !== size;
        }))
        throw new Error('Vault identity is missing or corrupt; refusing to replace it.');
}
export function createIdentityMaterial() {
    const ec = keygenEd25519(), dsa = keygenMLDSA87();
    const dh = keygenX25519(), kem = keygenMLKEM1024();
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
export function identityBinding(id) {
    validateLocalIdentity(id);
    const input = concatBytes(new TextEncoder().encode('ECP-VAULT-IDENTITY-v1'), ...Object.keys(lengths).map((name) => id[name]));
    try {
        return encodeBase64URL(sha256(input));
    }
    finally {
        input.fill(0);
    }
}
export function clearIdentityMaterial(id) {
    for (const name of Object.keys(lengths))
        id[name].fill(0);
}
//# sourceMappingURL=identity-material.js.map