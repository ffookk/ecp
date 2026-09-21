import {
  buildHeader,
  validatePacket,
  encodeUTF8,
  decodeUTF8,
  zeros,
} from './codec.js';
import { Config } from './config.js';
import {
  encodeBase64URL,
  decodeBase64URL,
  concatBytes,
  sha256,
  hkdfSHA256,
  hmacSHA256,
  encryptGCM,
  decryptGCM,
  encapsulateMLKEM1024,
  decapsulateMLKEM1024,
  keygenX25519,
  getSharedSecretX25519,
  keygenMLKEM1024,
  signComposite,
  verifyComposite,
  constantTimeCompare,
  randomUUID,
} from './crypto.js';
import {
  getLocalIdentity,
  serializeIdentityPublic,
  parseIdentityPublic,
  calculateFingerprint,
} from './identity.js';
import { DB } from './storage.js';
import { withStateLock } from './locks.js';
import type { Session, Message } from './types.js';

const INIT_FIXED = 4225 * 2 + 32 + 1568 + 4691;
const INIT_SIZE = 12 + INIT_FIXED + 16;
const RESP_SIZE = 3196;
const MSG_OVERHEAD = 3220;
const UINT32_MAX = 0xffffffff;

// These buffers are per-operation derived values, never identity/session arrays.
const clear = (...values: Uint8Array[]) => values.forEach((v) => v.fill(0));

const deriveSymmetric = (
  mk: Uint8Array,
  keyLabel: string,
  nonceLabel: string,
) => ({
  key: hkdfSHA256(mk, zeros(32), encodeUTF8(keyLabel), 32),
  nonce: hmacSHA256(mk, encodeUTF8(nonceLabel)).slice(0, 12),
});

const kdfRoot = (rk: Uint8Array, dh: Uint8Array, kem: Uint8Array) => {
  const ikm = concatBytes(dh, kem);
  try {
    return hkdfSHA256(ikm, rk, encodeUTF8('ECP-DR-RK-v2'), 64);
  } finally {
    clear(ikm, dh, kem);
  }
};

const initSecret = (dh: Uint8Array, kem: Uint8Array) => {
  const ikm = concatBytes(encodeUTF8('ECP-INIT-v2'), dh, kem);
  try {
    return hkdfSHA256(ikm, zeros(32), encodeUTF8(''), 32);
  } finally {
    clear(ikm, dh, kem);
  }
};

const deriveInitKeys = (sk: Uint8Array) => {
  const mk = hkdfSHA256(sk, zeros(32), encodeUTF8('ECP-INIT-MESSAGE-v2'), 32);
  try {
    return deriveSymmetric(mk, 'ECP-AES256GCM-v2', 'ECP-INIT-NONCE-v2');
  } finally {
    clear(mk);
  }
};

const deriveMsgKeys = (ck: Uint8Array) => {
  const mk = hmacSHA256(ck, new Uint8Array([0x01]));
  return {
    ...deriveSymmetric(mk, 'ECP-AES256GCM-v2', 'ECP-NONCE-v2'),
    nextCk: hmacSHA256(ck, new Uint8Array([0x02])),
    mk,
  };
};

const conversationId = (ek: Uint8Array, kemCt: Uint8Array) =>
  encodeBase64URL(
    sha256(concatBytes(encodeUTF8('ECP-CONVERSATION-v2'), ek, kemCt)).slice(
      0,
      16,
    ),
  );

async function requirePeer(contactFp: string, expectedBundle?: string) {
  const contact = await DB.get('contacts', contactFp);
  if (!contact?.verified)
    throw new Error('Peer must be independently verified before use.');
  const bytes = decodeBase64URL(contact.bundle);
  if (bytes.length !== 4225 || calculateFingerprint(bytes) !== contactFp)
    throw new Error('Peer identity is inconsistent.');
  if (
    expectedBundle !== undefined &&
    !constantTimeCompare(bytes, decodeBase64URL(expectedBundle))
  )
    throw new Error('Peer identity does not match the channel.');
  return { contact, bytes, publicIdentity: parseIdentityPublic(bytes) };
}

function checkSession(session: Session) {
  if (session.version !== 2)
    throw new Error('Unsupported stored protocol version.');
  for (const counter of [session.Ns, session.Nr, session.PN])
    if (!Number.isSafeInteger(counter) || counter < 0 || counter > UINT32_MAX)
      throw new Error('Invalid ratchet counter.');
}

function messageRecord(session: Session, text: string, isMe: boolean): Message {
  return {
    id: randomUUID(),
    contactFp: session.contactFp,
    conversationId: session.conversationId,
    isMe,
    text,
    timestamp: Date.now(),
  };
}

/** INIT is exclusively a control packet. User content is sent after key confirmation. */
export const CreateInit = (contactFp: string) =>
  withStateLock(async () => {
    const local = await getLocalIdentity();
    const localPub = serializeIdentityPublic(local);
    if (contactFp === calculateFingerprint(localPub))
      throw new Error('Self-messaging is prohibited.');
    const {
      contact,
      bytes: peerPub,
      publicIdentity: peer,
    } = await requirePeer(contactFp);
    if (await DB.get('sessions', contactFp))
      throw new Error(
        'Reset the existing channel before starting another handshake.',
      );

    const ek = keygenX25519();
    const kem = encapsulateMLKEM1024(peer.kemPk);
    const SK = initSecret(
      getSharedSecretX25519(ek.secretKey, peer.dhPk),
      kem.sharedSecret,
    );
    const transcript = concatBytes(
      encodeUTF8('ECP-INIT-v2'),
      localPub,
      peerPub,
      ek.publicKey,
      kem.cipherText,
    );
    const signature = signComposite(transcript, local.ecSk, local.dsaSk);
    const fixed = concatBytes(
      localPub,
      peerPub,
      ek.publicKey,
      kem.cipherText,
      signature,
    );
    const header = buildHeader(Config.PACKET_TYPES.INIT, fixed.length + 16);
    const symmetric = deriveInitKeys(SK);
    let ciphertext: Uint8Array;
    try {
      ciphertext = encryptGCM(
        symmetric.key,
        symmetric.nonce,
        zeros(0),
        concatBytes(header, fixed),
      );
    } finally {
      clear(symmetric.key, symmetric.nonce);
    }
    const session: Session = {
      contactFp,
      version: 2,
      conversationId: conversationId(ek.publicKey, kem.cipherText),
      peerIdentity: contact.bundle,
      DHs: { sk: ek.secretKey, pk: ek.publicKey },
      KEMs: { sk: local.kemSk, pk: local.kemPk },
      KEMr: { pk: peer.kemPk },
      RK: hkdfSHA256(SK, zeros(32), encodeUTF8('ECP-DR-ROOT-v2'), 32),
      Ns: 0,
      Nr: 0,
      PN: 0,
      SK,
      state: 'HANDSHAKE_SENT',
    };
    await DB.putMany([['sessions', session]]);
    return { packet: concatBytes(header, fixed, ciphertext), session };
  });

export const ProcessInit = (packet: Uint8Array) =>
  withStateLock(async () => {
    validatePacket(packet, Config.PACKET_TYPES.INIT);
    if (packet.length !== INIT_SIZE)
      throw new Error(
        'INIT must be a control-only packet with no user content.',
      );
    const local = await getLocalIdentity();
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
    const {
      contact,
      bytes: knownBytes,
      publicIdentity: sender,
    } = await requirePeer(senderFp);
    if (!constantTimeCompare(senderBytes, knownBytes))
      throw new Error('INIT sender is not the verified peer.');
    const transcript = concatBytes(
      encodeUTF8('ECP-INIT-v2'),
      senderBytes,
      receiverBytes,
      ek,
      kemCt,
    );
    if (!verifyComposite(signature, transcript, sender.ecPk, sender.dsaPk))
      throw new Error('INIT packet signature verification failed.');
    // Transcript identity survives randomized signatures, channel reset and deletion.
    const replayId = encodeBase64URL(
      sha256(concatBytes(encodeUTF8('ECP-INIT-REPLAY-v2'), transcript)),
    );
    if (await DB.get('replays', replayId))
      throw new Error('INIT packet replay detected.');
    if (await DB.get('sessions', senderFp))
      throw new Error(
        'An active channel cannot be replaced by an incoming INIT.',
      );

    const SK = initSecret(
      getSharedSecretX25519(local.dhSk, ek),
      decapsulateMLKEM1024(kemCt, local.kemSk),
    );
    try {
      const symmetric = deriveInitKeys(SK);
      let plaintext: Uint8Array;
      try {
        plaintext = decryptGCM(
          symmetric.key,
          symmetric.nonce,
          packet.slice(offset),
          packet.slice(0, offset),
        );
      } finally {
        clear(symmetric.key, symmetric.nonce);
      }
      if (plaintext.length) {
        clear(plaintext);
        throw new Error('INIT cannot contain user content.');
      }
      const RK0 = hkdfSHA256(SK, zeros(32), encodeUTF8('ECP-DR-ROOT-v2'), 32);
      const dhs = keygenX25519();
      const kems = keygenMLKEM1024();
      const kem = encapsulateMLKEM1024(sender.kemPk);
      const root = kdfRoot(
        RK0,
        getSharedSecretX25519(dhs.secretKey, ek),
        kem.sharedSecret,
      );
      clear(RK0);
      const respPayload = concatBytes(
        dhs.publicKey,
        kem.cipherText,
        kems.publicKey,
      );
      const respHeader = buildHeader(
        Config.PACKET_TYPES.RESP,
        respPayload.length + 16,
      );
      const responseKeys = deriveSymmetric(
        SK,
        'ECP-RESP-v2',
        'ECP-RESP-NONCE-v2',
      );
      let respPacket: Uint8Array;
      try {
        respPacket = concatBytes(
          respHeader,
          encryptGCM(
            responseKeys.key,
            responseKeys.nonce,
            respPayload,
            respHeader,
          ),
        );
      } finally {
        clear(responseKeys.key, responseKeys.nonce);
      }
      const session: Session = {
        contactFp: senderFp,
        version: 2,
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
      await DB.putMany([
        ['replays', { id: replayId, contactFp: senderFp }],
        ['sessions', session],
      ]);
      return { session, respPacket };
    } finally {
      clear(SK);
    }
  });

export const ProcessResp = (packet: Uint8Array) =>
  withStateLock(async () => {
    validatePacket(packet, Config.PACKET_TYPES.RESP);
    if (packet.length !== RESP_SIZE)
      throw new Error('Invalid RESP packet length.');
    const digest = encodeBase64URL(sha256(packet));
    const sessions = await DB.getAll('sessions');
    for (const session of sessions) {
      if (
        session.version === 2 &&
        session.state === 'ESTABLISHED' &&
        session.acceptedRespHash === digest
      ) {
        await requirePeer(session.contactFp, session.peerIdentity);
        return { alreadyEstablished: true, session };
      }
    }
    for (const session of sessions) {
      if (
        session.version !== 2 ||
        session.state !== 'HANDSHAKE_SENT' ||
        !session.SK
      )
        continue;
      checkSession(session);
      await requirePeer(session.contactFp, session.peerIdentity);
      const symmetric = deriveSymmetric(
        session.SK,
        'ECP-RESP-v2',
        'ECP-RESP-NONCE-v2',
      );
      let plaintext: Uint8Array;
      try {
        plaintext = decryptGCM(
          symmetric.key,
          symmetric.nonce,
          packet.slice(12),
          packet.slice(0, 12),
        );
      } catch {
        continue;
      } finally {
        clear(symmetric.key, symmetric.nonce);
      }
      const dh = plaintext.slice(0, 32);
      const kemCt = plaintext.slice(32, 1600);
      const kemPub = plaintext.slice(1600, 3168);
      const local = await getLocalIdentity();
      const root = kdfRoot(
        session.RK,
        getSharedSecretX25519(session.DHs.sk, dh),
        decapsulateMLKEM1024(kemCt, local.kemSk),
      );
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
      await DB.putMany([['sessions', session]]);
      return { alreadyEstablished: false, session };
    }
    throw new Error(
      'RESP authentication failed: no matching pending handshake or exact accepted response.',
    );
  });

function stepDH(session: Session) {
  if (!session.DHr || !session.KEMr)
    throw new Error('Remote ratchet keys are missing.');
  const dh = keygenX25519();
  const kemKeys = keygenMLKEM1024();
  const kem = encapsulateMLKEM1024(session.KEMr.pk);
  const root = kdfRoot(
    session.RK,
    getSharedSecretX25519(dh.secretKey, session.DHr.pk),
    kem.sharedSecret,
  );
  session.RK = root.slice(0, 32);
  session.CKs = root.slice(32, 64);
  clear(root);
  session.DHs = { sk: dh.secretKey, pk: dh.publicKey };
  session.KEMs = { sk: kemKeys.secretKey, pk: kemKeys.publicKey };
  session.pendingKemCt = kem.cipherText;
  session.PN = session.Ns;
  session.Ns = 0;
}

export const EncryptMessage = (contactFp: string, text: string) =>
  withStateLock(async () => {
    if (
      typeof text !== 'string' ||
      text.length > Config.MAX_PACKET_SIZE - MSG_OVERHEAD
    )
      throw new Error('Message exceeds maximum size.');
    const plaintext = encodeUTF8(text);
    try {
      if (plaintext.length > Config.MAX_PACKET_SIZE - MSG_OVERHEAD)
        throw new Error('Message exceeds maximum size.');
      const session = await DB.get('sessions', contactFp);
      if (!session || session.state !== 'ESTABLISHED')
        throw new Error(
          'An established channel is required before sending content.',
        );
      checkSession(session);
      await requirePeer(contactFp, session.peerIdentity);
      if (!session.CKs) stepDH(session);
      if (!session.CKs || !session.pendingKemCt || !session.KEMs)
        throw new Error('Missing sending chain.');
      if (session.Ns >= UINT32_MAX)
        throw new Error('Message counter exhausted; reset the channel.');
      const symmetric = deriveMsgKeys(session.CKs);
      const cId = decodeBase64URL(session.conversationId);
      const localPub = serializeIdentityPublic(await getLocalIdentity());
      const counters = zeros(8);
      const view = new DataView(counters.buffer);
      view.setUint32(0, session.PN);
      view.setUint32(4, session.Ns);
      const msgHeader = concatBytes(
        cId,
        session.DHs.pk,
        session.pendingKemCt,
        session.KEMs.pk,
        counters,
      );
      const aad = concatBytes(
        encodeUTF8('ECP-MSG-v2'),
        cId,
        localPub,
        decodeBase64URL(session.peerIdentity),
        msgHeader,
      );
      let ciphertext: Uint8Array;
      try {
        ciphertext = encryptGCM(symmetric.key, symmetric.nonce, plaintext, aad);
      } finally {
        clear(symmetric.key, symmetric.nonce, symmetric.mk);
      }
      session.CKs = symmetric.nextCk;
      session.Ns++;
      const payload = concatBytes(msgHeader, ciphertext);
      const packet = concatBytes(
        buildHeader(Config.PACKET_TYPES.MSG, payload.length),
        payload,
      );
      await DB.putMany([
        ['sessions', session],
        ['messages', messageRecord(session, text, true)],
      ]);
      return { packet, session };
    } finally {
      clear(plaintext);
    }
  });

export const DecryptMessage = (packet: Uint8Array) =>
  withStateLock(async () => {
    validatePacket(packet, Config.PACKET_TYPES.MSG);
    if (packet.length < MSG_OVERHEAD)
      throw new Error('Invalid message packet length.');
    let offset = 12;
    const cId = packet.slice(offset, (offset += 16));
    const dh = packet.slice(offset, (offset += 32));
    const kemCt = packet.slice(offset, (offset += 1568));
    const kemPub = packet.slice(offset, (offset += 1568));
    const view = new DataView(
      packet.buffer,
      packet.byteOffset,
      packet.byteLength,
    );
    const pn = view.getUint32(offset);
    offset += 4;
    const n = view.getUint32(offset);
    offset += 4;
    if (n >= UINT32_MAX) throw new Error('Message counter exhausted.');
    const session = await DB.getByIndex(
      'sessions',
      'conversationId',
      encodeBase64URL(cId),
    );
    if (!session || session.state !== 'ESTABLISHED' || !session.DHr)
      throw new Error('Established session not found for this message.');
    checkSession(session);
    await requirePeer(session.contactFp, session.peerIdentity);
    const aad = concatBytes(
      encodeUTF8('ECP-MSG-v2'),
      cId,
      decodeBase64URL(session.peerIdentity),
      serializeIdentityPublic(await getLocalIdentity()),
      packet.slice(12, offset),
    );
    const tag = encodeBase64URL(dh);
    const cacheKey = `${tag}_${n}`;
    const skipped = { ...session.skippedKeys };
    if (Object.keys(skipped).length > Config.MAX_SKIP)
      throw new Error('Invalid skipped-key cache.');
    let plaintext: Uint8Array;
    if (skipped[cacheKey]) {
      const mk = decodeBase64URL(skipped[cacheKey]);
      const symmetric = deriveSymmetric(mk, 'ECP-AES256GCM-v2', 'ECP-NONCE-v2');
      try {
        plaintext = decryptGCM(
          symmetric.key,
          symmetric.nonce,
          packet.slice(offset),
          aad,
        );
      } finally {
        clear(mk, symmetric.key, symmetric.nonce);
      }
      delete skipped[cacheKey];
    } else {
      const changed = !constantTimeCompare(dh, session.DHr.pk);
      const oldSkip = changed ? pn - session.Nr : 0;
      const newSkip = n - (changed ? 0 : session.Nr);
      // Both counters are unauthenticated here: validate the total before any loop or DH/KEM work.
      if (oldSkip < 0 || newSkip < 0)
        throw new Error('Message out of order or replayed.');
      if (
        oldSkip > Config.MAX_SKIP ||
        newSkip > Config.MAX_SKIP ||
        oldSkip + newSkip > Config.MAX_SKIP
      )
        throw new Error('Excessive message gap.');
      if (oldSkip && !session.CKr)
        throw new Error('Missing previous receiving chain.');
      const remember = (key: string, mk: Uint8Array) => {
        if (Object.keys(skipped).length >= Config.MAX_SKIP)
          delete skipped[Object.keys(skipped)[0]];
        skipped[key] = encodeBase64URL(mk);
      };
      let chain = session.CKr;
      for (let i = 0; i < oldSkip; i++) {
        const derived = deriveMsgKeys(chain!);
        remember(
          `${encodeBase64URL(session.DHr.pk)}_${session.Nr + i}`,
          derived.mk,
        );
        chain = derived.nextCk;
        clear(derived.mk, derived.key, derived.nonce);
      }
      if (changed) {
        if (!session.KEMs) throw new Error('Missing local KEM keys.');
        const receivedRoot = kdfRoot(
          session.RK,
          getSharedSecretX25519(session.DHs.sk, dh),
          decapsulateMLKEM1024(kemCt, session.KEMs.sk),
        );
        session.RK = receivedRoot.slice(0, 32);
        chain = receivedRoot.slice(32, 64);
        clear(receivedRoot);
        session.DHr = { pk: dh };
        session.KEMr = { pk: kemPub };
        session.Nr = 0;
        stepDH(session);
      }
      for (let i = 0; i < newSkip; i++) {
        if (!chain) throw new Error('Missing receiving chain.');
        const derived = deriveMsgKeys(chain);
        remember(`${tag}_${session.Nr + i}`, derived.mk);
        chain = derived.nextCk;
        clear(derived.mk, derived.key, derived.nonce);
      }
      if (!chain) throw new Error('Missing receiving chain.');
      const derived = deriveMsgKeys(chain);
      try {
        plaintext = decryptGCM(
          derived.key,
          derived.nonce,
          packet.slice(offset),
          aad,
        );
      } finally {
        clear(derived.key, derived.nonce, derived.mk);
      }
      // Apply the new receiving key after the DH/send-chain transition, never restore an old copy.
      session.CKr = derived.nextCk;
      session.Nr = n + 1;
    }
    session.skippedKeys = skipped;
    delete session.lastRespPacket;
    let text: string;
    try {
      text = decodeUTF8(plaintext);
    } finally {
      clear(plaintext);
    }
    await DB.putMany([
      ['sessions', session],
      ['messages', messageRecord(session, text, false)],
    ]);
    return { session, plaintext: text };
  });
