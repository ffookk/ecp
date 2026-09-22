import { buildHeader, validatePacket, encodeUTF8, decodeUTF8, zeros, } from './codec.js';
import { Config } from './config.js';
import { encodeBase64URL, decodeBase64URL, concatBytes, sha256, hkdfSHA256, hmacSHA256, PACKET_AEAD_OVERHEAD, encryptPacket, decryptPacket, encapsulateMLKEM1024, decapsulateMLKEM1024, keygenX25519, getSharedSecretX25519, keygenMLKEM1024, signComposite, verifyComposite, constantTimeCompare, randomUUID, } from './crypto.js';
import { getLocalIdentity, serializeIdentityPublic, parseIdentityPublic, calculateFingerprint, } from './identity.js';
import { DB, Vault } from './storage.js';
import { withStateLock } from './locks.js';
const INIT_FIXED = 4225 * 2 + 32 + 1568 + 4691;
const INIT_SIZE = 12 + INIT_FIXED + PACKET_AEAD_OVERHEAD;
const RESP_SIZE = 12 + 3168 + PACKET_AEAD_OVERHEAD;
const MSG_OVERHEAD = 3204 + PACKET_AEAD_OVERHEAD;
const UINT32_MAX = 0xffffffff;
const clear = (...values) => values.forEach((v) => v.fill(0));
const deriveSymmetric = (mk, keyLabel) => ({
    key: hkdfSHA256(mk, zeros(32), encodeUTF8(keyLabel), 32),
});
const kdfRoot = (rk, dh, kem) => {
    const ikm = concatBytes(dh, kem);
    try {
        return hkdfSHA256(ikm, rk, encodeUTF8('ECP-DR-RK-v3'), 64);
    }
    finally {
        clear(ikm, dh, kem);
    }
};
const initSecret = (dh, kem) => {
    const ikm = concatBytes(encodeUTF8('ECP-INIT-v3'), dh, kem);
    try {
        return hkdfSHA256(ikm, zeros(32), encodeUTF8(''), 32);
    }
    finally {
        clear(ikm, dh, kem);
    }
};
const deriveInitKeys = (sk) => {
    const mk = hkdfSHA256(sk, zeros(32), encodeUTF8('ECP-INIT-MESSAGE-v3'), 32);
    try {
        return deriveSymmetric(mk, 'ECP-AES256GCMSIV-v3');
    }
    finally {
        clear(mk);
    }
};
const deriveMsgKeys = (ck) => {
    const mk = hmacSHA256(ck, new Uint8Array([0x01]));
    return {
        ...deriveSymmetric(mk, 'ECP-AES256GCMSIV-v3'),
        nextCk: hmacSHA256(ck, new Uint8Array([0x02])),
        mk,
    };
};
const conversationId = (ek, kemCt) => encodeBase64URL(sha256(concatBytes(encodeUTF8('ECP-CONVERSATION-v3'), ek, kemCt)).slice(0, 16));
async function requirePeer(contactFp, expectedBundle) {
    const contact = await DB.get('contacts', contactFp);
    if (!contact?.verified)
        throw new Error('Peer must be independently verified before use.');
    const bytes = decodeBase64URL(contact.bundle);
    if (bytes.length !== 4225 || calculateFingerprint(bytes) !== contactFp)
        throw new Error('Peer identity is inconsistent.');
    if (expectedBundle !== undefined &&
        !constantTimeCompare(bytes, decodeBase64URL(expectedBundle)))
        throw new Error('Peer identity does not match the channel.');
    return { contact, bytes, publicIdentity: parseIdentityPublic(bytes) };
}
function checkSession(session) {
    if (session.version !== Config.WIRE_PROTOCOL_VERSION)
        throw new Error('Unsupported stored protocol version; reset the channel on both peers.');
    for (const counter of [session.Ns, session.Nr, session.PN])
        if (!Number.isSafeInteger(counter) || counter < 0 || counter > UINT32_MAX)
            throw new Error('Invalid ratchet counter.');
}
function messageRecord(session, text, isMe) {
    return {
        id: randomUUID(),
        contactFp: session.contactFp,
        conversationId: session.conversationId,
        isMe,
        text,
        timestamp: Date.now(),
    };
}
async function withProtocolState(operation) {
    const assertAccess = Vault.captureAccess();
    const access = async (action) => {
        assertAccess();
        const result = await action();
        assertAccess();
        return result;
    };
    return withStateLock(async () => {
        assertAccess();
        const result = await operation(access);
        assertAccess();
        return result;
    });
}
export const CreateInit = (contactFp) => withProtocolState(async (access) => {
    const local = await access(() => getLocalIdentity());
    const localPub = serializeIdentityPublic(local);
    if (contactFp === calculateFingerprint(localPub))
        throw new Error('Self-messaging is prohibited.');
    const { contact, bytes: peerPub, publicIdentity: peer, } = await access(() => requirePeer(contactFp));
    if (await access(() => DB.get('sessions', contactFp)))
        throw new Error('Reset the existing channel before starting another handshake.');
    const ek = keygenX25519();
    const kem = encapsulateMLKEM1024(peer.kemPk);
    const SK = initSecret(getSharedSecretX25519(ek.secretKey, peer.dhPk), kem.sharedSecret);
    const transcript = concatBytes(encodeUTF8('ECP-INIT-v3'), localPub, peerPub, ek.publicKey, kem.cipherText);
    const signature = signComposite(transcript, local.ecSk, local.dsaSk);
    const fixed = concatBytes(localPub, peerPub, ek.publicKey, kem.cipherText, signature);
    const header = buildHeader(Config.PACKET_TYPES.INIT, fixed.length + PACKET_AEAD_OVERHEAD);
    const symmetric = deriveInitKeys(SK);
    let ciphertext;
    try {
        ciphertext = encryptPacket(symmetric.key, zeros(0), concatBytes(header, fixed));
    }
    finally {
        clear(symmetric.key);
    }
    const session = {
        contactFp,
        version: Config.WIRE_PROTOCOL_VERSION,
        conversationId: conversationId(ek.publicKey, kem.cipherText),
        peerIdentity: contact.bundle,
        DHs: { sk: ek.secretKey, pk: ek.publicKey },
        KEMs: { sk: local.kemSk, pk: local.kemPk },
        KEMr: { pk: peer.kemPk },
        RK: hkdfSHA256(SK, zeros(32), encodeUTF8('ECP-DR-ROOT-v3'), 32),
        Ns: 0,
        Nr: 0,
        PN: 0,
        SK,
        state: 'HANDSHAKE_SENT',
    };
    await access(() => DB.putMany([['sessions', session]]));
    return { packet: concatBytes(header, fixed, ciphertext), session };
});
export const ProcessInit = (packet) => withProtocolState(async (access) => {
    validatePacket(packet, Config.PACKET_TYPES.INIT);
    if (packet.length !== INIT_SIZE)
        throw new Error('INIT must be a control-only packet with no user content.');
    const local = await access(() => getLocalIdentity());
    const localPub = serializeIdentityPublic(local);
    let offset = 12;
    const senderBytes = packet.slice(offset, (offset += 4225));
    const receiverBytes = packet.slice(offset, (offset += 4225));
    const ek = packet.slice(offset, (offset += 32));
    const kemCt = packet.slice(offset, (offset += 1568));
    const signature = packet.slice(offset, (offset += 4691));
    if (!constantTimeCompare(receiverBytes, localPub))
        throw new Error('INIT packet destination misrouted.');
    const senderFp = calculateFingerprint(senderBytes);
    if (senderFp === calculateFingerprint(localPub))
        throw new Error('Self-messaging is prohibited.');
    const { contact, bytes: knownBytes, publicIdentity: sender, } = await access(() => requirePeer(senderFp));
    if (!constantTimeCompare(senderBytes, knownBytes))
        throw new Error('INIT sender is not the verified peer.');
    const transcript = concatBytes(encodeUTF8('ECP-INIT-v3'), senderBytes, receiverBytes, ek, kemCt);
    if (!verifyComposite(signature, transcript, sender.ecPk, sender.dsaPk))
        throw new Error('INIT packet signature verification failed.');
    const replayId = encodeBase64URL(sha256(concatBytes(encodeUTF8('ECP-INIT-REPLAY-v3'), transcript)));
    if (await access(() => DB.get('replays', replayId)))
        throw new Error('INIT packet replay detected.');
    if (await access(() => DB.get('sessions', senderFp)))
        throw new Error('An active channel cannot be replaced by an incoming INIT.');
    const SK = initSecret(getSharedSecretX25519(local.dhSk, ek), decapsulateMLKEM1024(kemCt, local.kemSk));
    try {
        const symmetric = deriveInitKeys(SK);
        let plaintext;
        try {
            plaintext = decryptPacket(symmetric.key, packet.slice(offset), packet.slice(0, offset));
        }
        finally {
            clear(symmetric.key);
        }
        if (plaintext.length) {
            clear(plaintext);
            throw new Error('INIT cannot contain user content.');
        }
        const RK0 = hkdfSHA256(SK, zeros(32), encodeUTF8('ECP-DR-ROOT-v3'), 32);
        const dhs = keygenX25519();
        const kems = keygenMLKEM1024();
        const kem = encapsulateMLKEM1024(sender.kemPk);
        const root = kdfRoot(RK0, getSharedSecretX25519(dhs.secretKey, ek), kem.sharedSecret);
        clear(RK0);
        const respPayload = concatBytes(dhs.publicKey, kem.cipherText, kems.publicKey);
        const respHeader = buildHeader(Config.PACKET_TYPES.RESP, respPayload.length + PACKET_AEAD_OVERHEAD);
        const responseKeys = deriveSymmetric(SK, 'ECP-RESP-v3');
        let respPacket;
        try {
            respPacket = concatBytes(respHeader, encryptPacket(responseKeys.key, respPayload, respHeader));
        }
        finally {
            clear(responseKeys.key);
        }
        const session = {
            contactFp: senderFp,
            version: Config.WIRE_PROTOCOL_VERSION,
            conversationId: conversationId(ek, kemCt),
            peerIdentity: contact.bundle,
            DHs: { sk: dhs.secretKey, pk: dhs.publicKey },
            DHr: { pk: ek },
            KEMs: { sk: kems.secretKey, pk: kems.publicKey },
            KEMr: { pk: sender.kemPk },
            pendingKemCt: kem.cipherText,
            RK: root.slice(0, 32),
            CKs: root.slice(32, 64),
            Ns: 0,
            Nr: 0,
            PN: 0,
            state: 'ESTABLISHED',
            lastRespPacket: encodeBase64URL(respPacket),
        };
        clear(root);
        await access(() => DB.putMany([
            ['replays', { id: replayId, contactFp: senderFp }],
            ['sessions', session],
        ]));
        return { session, respPacket };
    }
    finally {
        clear(SK);
    }
});
export const ProcessResp = (packet) => withProtocolState(async (access) => {
    validatePacket(packet, Config.PACKET_TYPES.RESP);
    if (packet.length !== RESP_SIZE)
        throw new Error('Invalid RESP packet length.');
    const digest = encodeBase64URL(sha256(packet));
    const sessions = await access(() => DB.getAll('sessions'));
    for (const session of sessions) {
        if (session.version === Config.WIRE_PROTOCOL_VERSION &&
            session.state === 'ESTABLISHED' &&
            session.acceptedRespHash === digest) {
            await access(() => requirePeer(session.contactFp, session.peerIdentity));
            return { alreadyEstablished: true, session };
        }
    }
    for (const session of sessions) {
        if (session.version !== Config.WIRE_PROTOCOL_VERSION ||
            session.state !== 'HANDSHAKE_SENT' ||
            !session.SK)
            continue;
        checkSession(session);
        await access(() => requirePeer(session.contactFp, session.peerIdentity));
        const local = await access(() => getLocalIdentity());
        const symmetric = deriveSymmetric(session.SK, 'ECP-RESP-v3');
        let plaintext;
        try {
            plaintext = decryptPacket(symmetric.key, packet.slice(12), packet.slice(0, 12));
        }
        catch {
            continue;
        }
        finally {
            clear(symmetric.key);
        }
        const dh = plaintext.slice(0, 32);
        const kemCt = plaintext.slice(32, 1600);
        const kemPub = plaintext.slice(1600, 3168);
        const root = kdfRoot(session.RK, getSharedSecretX25519(session.DHs.sk, dh), decapsulateMLKEM1024(kemCt, local.kemSk));
        session.RK = root.slice(0, 32);
        session.CKr = root.slice(32, 64);
        clear(root, plaintext);
        delete session.CKs;
        session.DHr = { pk: dh };
        session.KEMs = { sk: local.kemSk, pk: local.kemPk };
        session.KEMr = { pk: kemPub };
        session.state = 'ESTABLISHED';
        session.acceptedRespHash = digest;
        delete session.SK;
        await access(() => DB.putMany([['sessions', session]]));
        return { alreadyEstablished: false, session };
    }
    throw new Error('RESP authentication failed: no matching pending handshake or exact accepted response.');
});
function stepDH(session) {
    if (!session.DHr || !session.KEMr)
        throw new Error('Remote ratchet keys are missing.');
    const dh = keygenX25519();
    const kemKeys = keygenMLKEM1024();
    const kem = encapsulateMLKEM1024(session.KEMr.pk);
    const root = kdfRoot(session.RK, getSharedSecretX25519(dh.secretKey, session.DHr.pk), kem.sharedSecret);
    session.RK = root.slice(0, 32);
    session.CKs = root.slice(32, 64);
    clear(root);
    session.DHs = { sk: dh.secretKey, pk: dh.publicKey };
    session.KEMs = { sk: kemKeys.secretKey, pk: kemKeys.publicKey };
    session.pendingKemCt = kem.cipherText;
    session.PN = session.Ns;
    session.Ns = 0;
}
export const EncryptMessage = (contactFp, text) => withProtocolState(async (access) => {
    if (typeof text !== 'string' ||
        text.length > Config.MAX_PACKET_SIZE - MSG_OVERHEAD)
        throw new Error('Message exceeds maximum size.');
    const plaintext = encodeUTF8(text);
    try {
        if (plaintext.length > Config.MAX_PACKET_SIZE - MSG_OVERHEAD)
            throw new Error('Message exceeds maximum size.');
        const session = await access(() => DB.get('sessions', contactFp));
        if (!session || session.state !== 'ESTABLISHED')
            throw new Error('An established channel is required before sending content.');
        checkSession(session);
        const { contact } = await access(() => requirePeer(contactFp, session.peerIdentity));
        if (!session.CKs)
            stepDH(session);
        if (!session.CKs || !session.pendingKemCt || !session.KEMs)
            throw new Error('Missing sending chain.');
        if (session.Ns >= UINT32_MAX)
            throw new Error('Message counter exhausted; reset the channel.');
        const cId = decodeBase64URL(session.conversationId);
        const localPub = serializeIdentityPublic(await access(() => getLocalIdentity()));
        const symmetric = deriveMsgKeys(session.CKs);
        const counters = zeros(8);
        const view = new DataView(counters.buffer);
        view.setUint32(0, session.PN);
        view.setUint32(4, session.Ns);
        const msgHeader = concatBytes(cId, session.DHs.pk, session.pendingKemCt, session.KEMs.pk, counters);
        const aad = concatBytes(encodeUTF8('ECP-MSG-v3'), cId, localPub, decodeBase64URL(session.peerIdentity), msgHeader);
        let ciphertext;
        try {
            ciphertext = encryptPacket(symmetric.key, plaintext, aad);
        }
        finally {
            clear(symmetric.key, symmetric.mk);
        }
        session.CKs = symmetric.nextCk;
        session.Ns++;
        const payload = concatBytes(msgHeader, ciphertext);
        const packet = concatBytes(buildHeader(Config.PACKET_TYPES.MSG, payload.length), payload);
        const message = messageRecord(session, text, true);
        const saved = contact.saveHistory === true;
        const entries = [['sessions', session]];
        if (saved)
            entries.push(['messages', message]);
        await access(() => DB.putMany(entries));
        return { packet, session, message, saved };
    }
    finally {
        clear(plaintext);
    }
});
export const DecryptMessage = (packet) => withProtocolState(async (access) => {
    validatePacket(packet, Config.PACKET_TYPES.MSG);
    if (packet.length < MSG_OVERHEAD)
        throw new Error('Invalid message packet length.');
    let offset = 12;
    const cId = packet.slice(offset, (offset += 16));
    const dh = packet.slice(offset, (offset += 32));
    const kemCt = packet.slice(offset, (offset += 1568));
    const kemPub = packet.slice(offset, (offset += 1568));
    const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
    const pn = view.getUint32(offset);
    offset += 4;
    const n = view.getUint32(offset);
    offset += 4;
    if (n >= UINT32_MAX)
        throw new Error('Message counter exhausted.');
    const session = await access(() => DB.getByIndex('sessions', 'conversationId', encodeBase64URL(cId)));
    if (!session || session.state !== 'ESTABLISHED' || !session.DHr)
        throw new Error('Established session not found for this message.');
    checkSession(session);
    const { contact } = await access(() => requirePeer(session.contactFp, session.peerIdentity));
    const aad = concatBytes(encodeUTF8('ECP-MSG-v3'), cId, decodeBase64URL(session.peerIdentity), serializeIdentityPublic(await access(() => getLocalIdentity())), packet.slice(12, offset));
    const tag = encodeBase64URL(dh);
    const cacheKey = `${tag}_${n}`;
    const skipped = { ...session.skippedKeys };
    if (Object.keys(skipped).length > Config.MAX_SKIP)
        throw new Error('Invalid skipped-key cache.');
    let plaintext;
    if (skipped[cacheKey]) {
        const mk = decodeBase64URL(skipped[cacheKey]);
        const symmetric = deriveSymmetric(mk, 'ECP-AES256GCMSIV-v3');
        try {
            plaintext = decryptPacket(symmetric.key, packet.slice(offset), aad);
        }
        finally {
            clear(mk, symmetric.key);
        }
        delete skipped[cacheKey];
    }
    else {
        const changed = !constantTimeCompare(dh, session.DHr.pk);
        const oldSkip = changed ? pn - session.Nr : 0;
        const newSkip = n - (changed ? 0 : session.Nr);
        if (oldSkip < 0 || newSkip < 0)
            throw new Error('Message out of order or replayed.');
        if (oldSkip > Config.MAX_SKIP ||
            newSkip > Config.MAX_SKIP ||
            oldSkip + newSkip > Config.MAX_SKIP)
            throw new Error('Excessive message gap.');
        if (oldSkip && !session.CKr)
            throw new Error('Missing previous receiving chain.');
        const remember = (key, mk) => {
            if (Object.keys(skipped).length >= Config.MAX_SKIP)
                delete skipped[Object.keys(skipped)[0]];
            skipped[key] = encodeBase64URL(mk);
        };
        let chain = session.CKr;
        for (let i = 0; i < oldSkip; i++) {
            const derived = deriveMsgKeys(chain);
            remember(`${encodeBase64URL(session.DHr.pk)}_${session.Nr + i}`, derived.mk);
            chain = derived.nextCk;
            clear(derived.mk, derived.key);
        }
        if (changed) {
            if (!session.KEMs)
                throw new Error('Missing local KEM keys.');
            const receivedRoot = kdfRoot(session.RK, getSharedSecretX25519(session.DHs.sk, dh), decapsulateMLKEM1024(kemCt, session.KEMs.sk));
            session.RK = receivedRoot.slice(0, 32);
            chain = receivedRoot.slice(32, 64);
            clear(receivedRoot);
            session.DHr = { pk: dh };
            session.KEMr = { pk: kemPub };
            session.Nr = 0;
            stepDH(session);
        }
        for (let i = 0; i < newSkip; i++) {
            if (!chain)
                throw new Error('Missing receiving chain.');
            const derived = deriveMsgKeys(chain);
            remember(`${tag}_${session.Nr + i}`, derived.mk);
            chain = derived.nextCk;
            clear(derived.mk, derived.key);
        }
        if (!chain)
            throw new Error('Missing receiving chain.');
        const derived = deriveMsgKeys(chain);
        try {
            plaintext = decryptPacket(derived.key, packet.slice(offset), aad);
        }
        finally {
            clear(derived.key, derived.mk);
        }
        session.CKr = derived.nextCk;
        session.Nr = n + 1;
    }
    session.skippedKeys = skipped;
    delete session.lastRespPacket;
    let text;
    try {
        text = decodeUTF8(plaintext);
    }
    finally {
        clear(plaintext);
    }
    const message = messageRecord(session, text, false);
    const saved = contact.saveHistory === true;
    const entries = [['sessions', session]];
    if (saved)
        entries.push(['messages', message]);
    await access(() => DB.putMany(entries));
    return { session, plaintext: text, message, saved };
});
//# sourceMappingURL=ratchet.js.map