import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createProtocolLab,
  changed,
  sequence,
} from './helpers/protocol-peers.mjs';

test('control-only handshake, exact RESP duplicates and several multi-message DH turns', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b, init, response } = await pair();
  assert.equal(init.packet.length, 14781);
  assert.equal(response.respPacket.length, 3208);
  assert.equal((await a.DB.getAll('messages')).length, 0);
  assert.equal((await b.DB.getAll('messages')).length, 0);
  await assert.rejects(a.CreateInit(b.fingerprint), /existing channel/);
  const beforeReplay = b.DB.snapshot();
  await assert.rejects(b.ProcessInit(init.packet), /replay/);
  assert.deepEqual(b.DB.snapshot(), beforeReplay);
  assert.equal(
    (await a.ProcessResp(response.respPacket)).alreadyEstablished,
    true,
  );
  await assert.rejects(
    a.ProcessResp(
      changed(response.respPacket, (p) => {
        p[p.length - 1] ^= 1;
      }),
    ),
    /authentication/,
  );
  for (let turn = 0; turn < 4; turn++) {
    const sender = turn % 2 ? b : a;
    const receiver = turn % 2 ? a : b;
    for (let n = 0; n < 3; n++) {
      const text = `turn ${turn}, message ${n}: secret`;
      const { packet } = await sender.EncryptMessage(
        receiver.fingerprint,
        text,
      );
      assert.equal((await receiver.DecryptMessage(packet)).plaintext, text);
    }
  }
  for (const peer of [a, b]) {
    assert.equal((await peer.DB.getAll('messages')).length, 12);
    assert.ok((await peer.DB.getAll('messages')).every((m) => m.contactFp));
  }
});

test('out-of-order messages use skipped keys once; tampering never changes storage', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const packets = [];
  for (let i = 0; i < 4; i++)
    packets.push(
      (await a.EncryptMessage(b.fingerprint, `message ${i}`)).packet,
    );
  const before = b.DB.snapshot();
  await assert.rejects(
    b.DecryptMessage(
      changed(packets[2], (p) => {
        p[p.length - 1] ^= 128;
      }),
    ),
  );
  assert.deepEqual(b.DB.snapshot(), before);
  assert.equal((await b.DecryptMessage(packets[2])).plaintext, 'message 2');
  const cached = b.DB.snapshot();
  await assert.rejects(
    b.DecryptMessage(
      changed(packets[0], (p) => {
        p[p.length - 1] ^= 1;
      }),
    ),
  );
  assert.deepEqual(
    b.DB.snapshot(),
    cached,
    'a forged old message must not consume its cached key',
  );
  for (const i of [0, 1, 3])
    assert.equal(
      (await b.DecryptMessage(packets[i])).plaintext,
      `message ${i}`,
    );
  const after = b.DB.snapshot();
  await assert.rejects(b.DecryptMessage(packets[0]));
  assert.deepEqual(b.DB.snapshot(), after);
});

test('delayed messages from the previous DH chain remain decryptable once', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const old = [];
  for (let i = 0; i < 3; i++)
    old.push((await a.EncryptMessage(b.fingerprint, `old ${i}`)).packet);
  await b.DecryptMessage(old[0]);
  await a.DecryptMessage(
    (await b.EncryptMessage(a.fingerprint, 'advance')).packet,
  );
  assert.equal(
    (
      await b.DecryptMessage(
        (await a.EncryptMessage(b.fingerprint, 'new chain')).packet,
      )
    ).plaintext,
    'new chain',
  );
  for (const i of [2, 1])
    assert.equal((await b.DecryptMessage(old[i])).plaintext, `old ${i}`);
  const beforeReplay = b.DB.snapshot();
  await assert.rejects(b.DecryptMessage(old[2]));
  assert.deepEqual(b.DB.snapshot(), beforeReplay);
});

test(
  'unauthenticated PN/N and aggregate skip requests are bounded before ratchet work',
  { timeout: 5000 },
  async (t) => {
    const { pair } = await createProtocolLab(t);
    const { a, b } = await pair();
    await b.DecryptMessage(
      (await a.EncryptMessage(b.fingerprint, 'first')).packet,
    );
    await a.DecryptMessage(
      (await b.EncryptMessage(a.fingerprint, 'reply')).packet,
    );
    const { packet } = await a.EncryptMessage(b.fingerprint, 'new turn');
    const before = b.DB.snapshot();
    const nr = (await b.DB.get('sessions', a.fingerprint)).Nr;
    const cases = [
      changed(packet, (_, v) => v.setUint32(3196, 0xffffffff)),
      changed(packet, (_, v) => v.setUint32(3200, 0xffffffff)),
      changed(packet, (_, v) => {
        v.setUint32(3196, nr + 75);
        v.setUint32(3200, 50);
      }),
    ];
    const start = performance.now();
    for (const malicious of cases)
      await assert.rejects(b.DecryptMessage(malicious), /gap|counter/);
    assert.ok(
      performance.now() - start < 1500,
      'small malicious frames must reject promptly',
    );
    assert.deepEqual(b.DB.snapshot(), before);
    assert.equal((await b.DecryptMessage(packet)).plaintext, 'new turn');
  },
);

test('concurrent sends consume distinct chain positions and remain decryptable', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      a.EncryptMessage(b.fingerprint, `parallel ${i}`),
    ),
  );
  assert.deepEqual(
    results.map(({ packet }) => sequence(packet)),
    [0, 1, 2, 3, 4, 5, 6, 7],
  );
  const received = await Promise.all(
    results.map(({ packet }) => b.DecryptMessage(packet)),
  );
  assert.deepEqual(
    received.map((r) => r.plaintext),
    Array.from({ length: 8 }, (_, i) => `parallel ${i}`),
  );
  assert.equal((await a.DB.getAll('messages')).length, 8);
  assert.equal((await b.DB.getAll('messages')).length, 8);
});

test('simultaneous send and receive preserves both ratchet directions', async (t) => {
  const { pair } = await createProtocolLab(t);
  for (const receiveFirst of [false, true]) {
    const { a, b } = await pair();
    await a.DecryptMessage(
      (await b.EncryptMessage(a.fingerprint, 'B0')).packet,
    );
    await b.DecryptMessage(
      (await a.EncryptMessage(b.fingerprint, 'A0')).packet,
    );
    const b1 = await b.EncryptMessage(a.fingerprint, 'B1');
    const operations = [
      () => a.EncryptMessage(b.fingerprint, 'A1'),
      () => a.DecryptMessage(b1.packet),
    ];
    if (receiveFirst) operations.reverse();
    const results = await Promise.all(operations.map((fn) => fn()));
    const sent = results.find((r) => r.packet);
    assert.equal(results.find((r) => 'plaintext' in r).plaintext, 'B1');
    assert.equal((await b.DecryptMessage(sent.packet)).plaintext, 'A1');
    assert.equal(
      (
        await b.DecryptMessage(
          (await a.EncryptMessage(b.fingerprint, 'A2')).packet,
        )
      ).plaintext,
      'A2',
    );
    assert.equal(
      (
        await a.DecryptMessage(
          (await b.EncryptMessage(a.fingerprint, 'B2')).packet,
        )
      ).plaintext,
      'B2',
    );
  }
});

test('authenticated transcript replay survives reset and randomized re-signing', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b, init } = await pair();
  await b.DB.delete('sessions', a.fingerprint);
  await assert.rejects(b.ProcessInit(init.packet), /replay/);
  const alternate = init.packet.slice();
  const c = a.cryptography;
  const signed = c.concatBytes(
    a.codec.encodeUTF8('ECP-INIT-v3'),
    alternate.slice(12, 10062),
  );
  alternate.set(c.signComposite(signed, a.local.ecSk, a.local.dsaSk), 10062);
  // The signed transcript is unchanged even though the randomized PQ signature differs.
  await assert.rejects(b.ProcessInit(alternate), /replay/);
  assert.equal((await b.DB.getAll('sessions')).length, 0);
  assert.equal((await b.DB.getAll('replays')).length, 1);
});

test('unknown or unverified identities cannot create or accept handshakes', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair(false);
  const contact = await a.DB.get('contacts', b.fingerprint);
  contact.verified = false;
  await a.DB.put('contacts', contact);
  await assert.rejects(a.CreateInit(b.fingerprint), /verified/);
  contact.verified = true;
  await a.DB.put('contacts', contact);
  const { packet } = await a.CreateInit(b.fingerprint);
  const sender = await b.DB.get('contacts', a.fingerprint);
  await b.DB.delete('contacts', a.fingerprint);
  const absent = b.DB.snapshot();
  await assert.rejects(b.ProcessInit(packet), /verified/);
  assert.deepEqual(b.DB.snapshot(), absent);
  sender.verified = false;
  await b.DB.put('contacts', sender);
  await assert.rejects(b.ProcessInit(packet), /verified/);
  sender.verified = true;
  await b.DB.put('contacts', sender);
  await b.ProcessInit(packet);
});

test('INIT rejects user content, legacy framing and replacement of an active session', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair(false);
  const init = await a.CreateInit(b.fingerprint);
  const withContent = new Uint8Array(init.packet.length + 1);
  withContent.set(init.packet);
  new DataView(withContent.buffer).setUint32(8, withContent.length - 12);
  await assert.rejects(b.ProcessInit(withContent), /control-only/);
  await assert.rejects(
    b.ProcessInit(
      changed(init.packet, (p) => {
        p[3] = 0x31;
        p[4] = 1;
      }),
    ),
  );
  await b.ProcessInit(init.packet);
  await a.DB.delete('sessions', b.fingerprint);
  const fresh = await a.CreateInit(b.fingerprint);
  const before = b.DB.snapshot();
  await assert.rejects(b.ProcessInit(fresh.packet), /active channel/);
  assert.deepEqual(b.DB.snapshot(), before);
});

test('exact framing and atomic commits prevent failed operations from advancing state/history', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b, response } = await pair();
  for (const malformed of [
    response.respPacket.slice(0, -1),
    a.cryptography.concatBytes(response.respPacket, new Uint8Array([0])),
  ])
    await assert.rejects(a.ProcessResp(malformed));
  const beforeSend = a.DB.snapshot();
  a.DB.failNextCommit();
  await assert.rejects(
    a.EncryptMessage(b.fingerprint, 'aborted'),
    /transaction abort/,
  );
  assert.deepEqual(a.DB.snapshot(), beforeSend);
  const { packet } = await a.EncryptMessage(b.fingerprint, 'committed');
  assert.equal(sequence(packet), 0);
  const beforeReceive = b.DB.snapshot();
  b.DB.failNextCommit();
  await assert.rejects(b.DecryptMessage(packet), /transaction abort/);
  assert.deepEqual(b.DB.snapshot(), beforeReceive);
  assert.equal((await b.DecryptMessage(packet)).plaintext, 'committed');
  assert.equal((await b.DB.getAll('messages')).length, 1);
});

test('handshake transaction failure commits neither replay records nor session state', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair(false);
  const { packet } = await a.CreateInit(b.fingerprint);
  const beforeInit = b.DB.snapshot();
  b.DB.failNextCommit();
  await assert.rejects(b.ProcessInit(packet), /transaction abort/);
  assert.deepEqual(b.DB.snapshot(), beforeInit);
  const { respPacket } = await b.ProcessInit(packet);
  const beforeResp = a.DB.snapshot();
  await assert.rejects(
    a.ProcessResp(
      changed(respPacket, (p) => {
        p[p.length - 1] ^= 1;
      }),
    ),
    /authentication/,
  );
  assert.deepEqual(a.DB.snapshot(), beforeResp);
  a.DB.failNextCommit();
  await assert.rejects(a.ProcessResp(respPacket), /transaction abort/);
  assert.deepEqual(a.DB.snapshot(), beforeResp);
  assert.equal((await a.ProcessResp(respPacket)).alreadyEstablished, false);
});

test('message limits and exhausted counters reject without changing storage', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const before = a.DB.snapshot();
  await assert.rejects(
    a.EncryptMessage(
      b.fingerprint,
      '\u{1f512}'.repeat(a.Config.MAX_PACKET_SIZE / 4),
    ),
    /maximum size/,
  );
  assert.deepEqual(a.DB.snapshot(), before);
  await a.EncryptMessage(b.fingerprint, 'initialize sending chain');
  const session = await a.DB.get('sessions', b.fingerprint);
  session.Ns = 0xffffffff;
  await a.DB.put('sessions', session);
  const exhausted = a.DB.snapshot();
  await assert.rejects(
    a.EncryptMessage(b.fingerprint, 'must not wrap'),
    /counter exhausted/,
  );
  assert.deepEqual(a.DB.snapshot(), exhausted);
});

test('locked reset cannot be followed by a stale protocol history write', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const sending = a.EncryptMessage(b.fingerprint, 'before reset');
  const resetting = a.withStateLock(async () => {
    await a.DB.delete('sessions', b.fingerprint);
    for (const m of await a.DB.getAll('messages'))
      if (m.contactFp === b.fingerprint) await a.DB.delete('messages', m.id);
  });
  await Promise.all([sending, resetting]);
  assert.equal((await a.DB.getAll('sessions')).length, 0);
  assert.equal((await a.DB.getAll('messages')).length, 0);
  await assert.rejects(
    a.EncryptMessage(b.fingerprint, 'after reset'),
    /established channel/,
  );
});

test('cloned and restored sending positions use fresh packet nonces and authenticate independently', async (t) => {
  const { pair, peer } = await createProtocolLab(t);
  const { a, b } = await pair();
  // The first initiator send creates a fresh DH chain. Clone only after it,
  // otherwise randomized DH keys would mask reuse of an existing position.
  await b.DecryptMessage(
    (await a.EncryptMessage(b.fingerprint, 'warmup')).packet,
  );
  const senderSnapshot = a.DB.snapshot(),
    receiverSnapshot = b.DB.snapshot();
  const fork = await peer(senderSnapshot),
    receiverFork = await peer(receiverSnapshot);
  const originalSession = await a.DB.get('sessions', b.fingerprint);
  assert.deepEqual(
    (await fork.DB.get('sessions', b.fingerprint)).CKs,
    originalSession.CKs,
  );
  const leftText = 'synthetic branch A',
    rightText = 'synthetic branch B';
  const left = (await a.EncryptMessage(b.fingerprint, leftText)).packet;
  const right = (await fork.EncryptMessage(b.fingerprint, rightText)).packet;
  assert.equal(sequence(left), sequence(right));
  assert.deepEqual(left.slice(0, 3204), right.slice(0, 3204));
  assert.notDeepEqual(left.slice(3204, 3216), right.slice(3204, 3216));
  // Derive the shared pre-fork message key and verify both sealed payloads.
  const c = a.cryptography;
  const mk = c.hmacSHA256(originalSession.CKs, new Uint8Array([1]));
  const key = c.hkdfSHA256(
    mk,
    new Uint8Array(32),
    a.codec.encodeUTF8('ECP-AES256GCMSIV-v3'),
    32,
  );
  const aad = c.concatBytes(
    a.codec.encodeUTF8('ECP-MSG-v3'),
    left.slice(12, 28),
    a.publicBytes,
    b.publicBytes,
    left.slice(12, 3204),
  );
  assert.equal(
    a.codec.decodeUTF8(c.decryptPacket(key, left.slice(3204), aad)),
    leftText,
  );
  assert.equal(
    a.codec.decodeUTF8(c.decryptPacket(key, right.slice(3204), aad)),
    rightText,
  );
  assert.equal((await b.DecryptMessage(left)).plaintext, leftText);
  assert.equal((await receiverFork.DecryptMessage(right)).plaintext, rightText);
  const consumed = b.DB.snapshot();
  await assert.rejects(b.DecryptMessage(right), /replayed|out of order/);
  assert.deepEqual(b.DB.snapshot(), consumed);

  a.DB.restore(senderSnapshot);
  const restored = (await a.EncryptMessage(b.fingerprint, leftText)).packet;
  assert.equal(sequence(restored), sequence(left));
  assert.notDeepEqual(restored.slice(3204, 3216), left.slice(3204, 3216));
  b.DB.restore(receiverSnapshot);
  assert.equal((await b.DecryptMessage(restored)).plaintext, leftText);
});

test('all packet types authenticate their transmitted nonce before changing storage', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair(false);
  const init = await a.CreateInit(b.fingerprint);
  let before = b.DB.snapshot();
  await assert.rejects(
    b.ProcessInit(
      changed(init.packet, (p) => {
        p[14753] ^= 1;
      }),
    ),
  );
  assert.deepEqual(b.DB.snapshot(), before);
  const response = await b.ProcessInit(init.packet);
  before = a.DB.snapshot();
  await assert.rejects(
    a.ProcessResp(
      changed(response.respPacket, (p) => {
        p[12] ^= 1;
      }),
    ),
  );
  assert.deepEqual(a.DB.snapshot(), before);
  await a.ProcessResp(response.respPacket);
  const first = (await a.EncryptMessage(b.fingerprint, 'first')).packet;
  const second = (await a.EncryptMessage(b.fingerprint, 'second')).packet;
  before = b.DB.snapshot();
  await assert.rejects(
    b.DecryptMessage(
      changed(second, (p) => {
        p[3204] ^= 1;
      }),
    ),
  );
  assert.deepEqual(b.DB.snapshot(), before);
  await b.DecryptMessage(second);
  before = b.DB.snapshot();
  await assert.rejects(
    b.DecryptMessage(
      changed(first, (p) => {
        p[3204] ^= 1;
      }),
    ),
  );
  assert.deepEqual(b.DB.snapshot(), before);
  assert.equal((await b.DecryptMessage(first)).plaintext, 'first');
});

test('a restored pre-INIT receiver uses a fresh RESP nonce under the same handshake key', async (t) => {
  const { pair, peer } = await createProtocolLab(t);
  const { a, b } = await pair(false);
  const { packet } = await a.CreateInit(b.fingerprint);
  const pending = await a.DB.get('sessions', b.fingerprint);
  const initiatorFork = await peer(a.DB.snapshot());
  const receiverFork = await peer(b.DB.snapshot());
  const left = (await b.ProcessInit(packet)).respPacket;
  const right = (await receiverFork.ProcessInit(packet)).respPacket;
  assert.deepEqual(left.slice(0, 12), right.slice(0, 12));
  assert.notDeepEqual(left.slice(12, 24), right.slice(12, 24));
  const key = a.cryptography.hkdfSHA256(
    pending.SK,
    new Uint8Array(32),
    a.codec.encodeUTF8('ECP-RESP-v3'),
    32,
  );
  for (const response of [left, right])
    assert.equal(
      a.cryptography.decryptPacket(
        key,
        response.slice(12),
        response.slice(0, 12),
      ).length,
      3168,
    );
  await a.ProcessResp(left);
  await initiatorFork.ProcessResp(right);
  assert.equal(
    (
      await b.DecryptMessage(
        (await a.EncryptMessage(b.fingerprint, 'left branch')).packet,
      )
    ).plaintext,
    'left branch',
  );
  assert.equal(
    (
      await receiverFork.DecryptMessage(
        (await initiatorFork.EncryptMessage(b.fingerprint, 'right branch'))
          .packet,
      )
    ).plaintext,
    'right branch',
  );
});

test('v2 wire framing and stored sessions fail closed without migration', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b, init, response } = await pair();
  const message = (await a.EncryptMessage(b.fingerprint, 'current')).packet;
  for (const [target, process, packet] of [
    [b, 'ProcessInit', init.packet],
    [a, 'ProcessResp', response.respPacket],
    [b, 'DecryptMessage', message],
  ]) {
    const before = target.DB.snapshot();
    await assert.rejects(
      target[process](
        changed(packet, (p) => {
          p[4] = 2;
        }),
      ),
      /version/,
    );
    await assert.rejects(
      target[process](
        changed(packet, (p) => {
          p[3] = 0x32;
          p[4] = 2;
        }),
      ),
      /magic/,
    );
    assert.deepEqual(target.DB.snapshot(), before);
  }
  assert.throws(() => a.codec.parseEnvelope('e2e2:AAAA'), /format/);
  const old = await a.DB.get('sessions', b.fingerprint);
  old.version = 2;
  await a.DB.put('sessions', old);
  const before = a.DB.snapshot();
  await assert.rejects(
    a.EncryptMessage(b.fingerprint, 'must reject'),
    /stored protocol version/,
  );
  assert.deepEqual(a.DB.snapshot(), before);
});

test('RNG failure releases no send result and commits no chain state or history', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  await b.DecryptMessage(
    (await a.EncryptMessage(b.fingerprint, 'warmup')).packet,
  );
  const before = a.DB.snapshot();
  const mock = t.mock.method(crypto, 'getRandomValues', () => {
    throw new Error('RNG unavailable');
  });
  await assert.rejects(
    a.EncryptMessage(b.fingerprint, 'must not send'),
    /RNG unavailable/,
  );
  assert.deepEqual(a.DB.snapshot(), before);
  mock.mock.restore();
  assert.equal(
    (
      await b.DecryptMessage(
        (await a.EncryptMessage(b.fingerprint, 'recovered')).packet,
      )
    ).plaintext,
    'recovered',
  );
});

test('queued protocol work cannot resume after a vault lock/unlock cycle', async (t) => {
  const { pair } = await createProtocolLab(t);
  for (const kind of ['create', 'init', 'resp', 'send', 'receive']) {
    const { a, b } = await pair(kind === 'send' || kind === 'receive');
    let target = a,
      action;
    if (kind === 'create') action = () => a.CreateInit(b.fingerprint);
    if (kind === 'init' || kind === 'resp') {
      const init = await a.CreateInit(b.fingerprint);
      if (kind === 'init') {
        target = b;
        action = () => b.ProcessInit(init.packet);
      } else {
        const response = await b.ProcessInit(init.packet);
        action = () => a.ProcessResp(response.respPacket);
      }
    }
    if (kind === 'send')
      action = () => a.EncryptMessage(b.fingerprint, 'stale send');
    if (kind === 'receive') {
      const message = await b.EncryptMessage(a.fingerprint, 'stale receive');
      action = () => a.DecryptMessage(message.packet);
    }
    const before = target.DB.snapshot();
    let release, entered;
    const started = new Promise((resolve) => {
      entered = resolve;
    });
    const held = target.withStateLock(
      () =>
        new Promise((resolve) => {
          release = resolve;
          entered();
        }),
    );
    await started;
    const rejected = assert.rejects(action(), /locked|changed/);
    target.Vault.lock();
    target.Vault.unlock();
    release();
    await held;
    await rejected;
    assert.deepEqual(target.DB.snapshot(), before, kind);
  }
});

test('vault invalidation during a protocol read cannot become a later-generation write', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const before = a.DB.snapshot();
  const get = a.DB.get;
  t.mock.method(a.DB, 'get', async (store, key) => {
    const value = await get.call(a.DB, store, key);
    if (store === 'sessions') {
      a.Vault.lock();
      a.Vault.unlock();
    }
    return value;
  });
  await assert.rejects(
    a.EncryptMessage(b.fingerprint, 'stale operation'),
    /locked|changed/,
  );
  assert.deepEqual(a.DB.snapshot(), before);
});

test('new message history defaults off for absent, false and non-boolean preferences', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const setPreference = async (peer, other, value) => {
    const contact = await peer.DB.get('contacts', other.fingerprint);
    if (value === undefined) delete contact.saveHistory;
    else contact.saveHistory = value;
    await peer.DB.put('contacts', contact);
  };
  for (const value of [undefined, false, 'true', 1]) {
    await setPreference(a, b, value);
    await setPreference(b, a, value);
    const sent = await a.EncryptMessage(
      b.fingerprint,
      `temporary ${String(value)}`,
    );
    const received = await b.DecryptMessage(sent.packet);
    assert.equal(sent.saved, false);
    assert.equal(received.saved, false);
    assert.equal(sent.message.text, received.plaintext);
    assert.equal(received.message.text, received.plaintext);
    assert.equal(sent.message.contactFp, b.fingerprint);
    assert.equal(received.message.contactFp, a.fingerprint);
    assert.equal(sent.message.isMe, true);
    assert.equal(received.message.isMe, false);
    assert.equal((await a.DB.getAll('messages')).length, 0);
    assert.equal((await b.DB.getAll('messages')).length, 0);
    const beforeReplay = b.DB.snapshot();
    await assert.rejects(
      b.DecryptMessage(sent.packet),
      /replayed|out of order/,
    );
    assert.deepEqual(b.DB.snapshot(), beforeReplay);
  }
});

test('each peer explicitly opts in and disabling history preserves old records', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const setPreference = async (peer, other, saveHistory) => {
    const contact = await peer.DB.get('contacts', other.fingerprint);
    await peer.DB.put('contacts', { ...contact, saveHistory });
  };
  await setPreference(a, b, true);
  await setPreference(b, a, false);
  const first = await a.EncryptMessage(b.fingerprint, 'saved only by sender');
  assert.equal(first.saved, true);
  assert.equal((await b.DecryptMessage(first.packet)).saved, false);
  assert.deepEqual(await a.DB.getAll('messages'), [first.message]);
  assert.deepEqual(await b.DB.getAll('messages'), []);

  await setPreference(a, b, false);
  await setPreference(b, a, true);
  const second = await a.EncryptMessage(
    b.fingerprint,
    'saved only by receiver',
  );
  const received = await b.DecryptMessage(second.packet);
  assert.equal(second.saved, false);
  assert.equal(received.saved, true);
  assert.deepEqual(await a.DB.getAll('messages'), [first.message]);
  assert.deepEqual(await b.DB.getAll('messages'), [received.message]);
});

test('queued send and receive use the preference current under the state lock', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  const changeBeforeOperation = async (peer, other, saveHistory, operation) => {
    let entered, release;
    const ready = new Promise((resolve) => {
      entered = resolve;
    });
    const held = peer.withStateLock(async () => {
      entered();
      await new Promise((resolve) => {
        release = resolve;
      });
      const contact = await peer.DB.get('contacts', other.fingerprint);
      await peer.DB.put('contacts', { ...contact, saveHistory });
    });
    await ready;
    const pending = operation();
    release();
    await held;
    return pending;
  };
  const sent = await changeBeforeOperation(a, b, false, () =>
    a.EncryptMessage(b.fingerprint, 'queued temporary'),
  );
  assert.equal(sent.saved, false);
  const received = await changeBeforeOperation(b, a, false, () =>
    b.DecryptMessage(sent.packet),
  );
  assert.equal(received.saved, false);
  assert.deepEqual(await a.DB.getAll('messages'), []);
  assert.deepEqual(await b.DB.getAll('messages'), []);

  const optedIn = await changeBeforeOperation(a, b, true, () =>
    a.EncryptMessage(b.fingerprint, 'queued saved'),
  );
  assert.equal(optedIn.saved, true);
  const receivedSaved = await changeBeforeOperation(b, a, true, () =>
    b.DecryptMessage(optedIn.packet),
  );
  assert.equal(receivedSaved.saved, true);
  assert.deepEqual(await a.DB.getAll('messages'), [optedIn.message]);
  assert.deepEqual(await b.DB.getAll('messages'), [receivedSaved.message]);
});

test('temporary messages still require an atomic state commit and successful authentication', async (t) => {
  const { pair } = await createProtocolLab(t);
  const { a, b } = await pair();
  for (const [peer, other] of [
    [a, b],
    [b, a],
  ]) {
    const contact = await peer.DB.get('contacts', other.fingerprint);
    delete contact.saveHistory;
    await peer.DB.put('contacts', contact);
  }
  const beforeSend = a.DB.snapshot();
  a.DB.failNextCommit();
  await assert.rejects(
    a.EncryptMessage(b.fingerprint, 'failed temporary'),
    /transaction abort/,
  );
  assert.deepEqual(a.DB.snapshot(), beforeSend);
  const sent = await a.EncryptMessage(b.fingerprint, 'temporary after retry');
  assert.equal(sequence(sent.packet), 0);
  const beforeReceive = b.DB.snapshot();
  await assert.rejects(
    b.DecryptMessage(
      changed(sent.packet, (packet) => {
        packet[packet.length - 1] ^= 1;
      }),
    ),
  );
  assert.deepEqual(b.DB.snapshot(), beforeReceive);
  b.DB.failNextCommit();
  await assert.rejects(b.DecryptMessage(sent.packet), /transaction abort/);
  assert.deepEqual(b.DB.snapshot(), beforeReceive);
  const received = await b.DecryptMessage(sent.packet);
  assert.equal(received.plaintext, 'temporary after retry');
  assert.equal(received.saved, false);
  assert.deepEqual(await b.DB.getAll('messages'), []);
});
