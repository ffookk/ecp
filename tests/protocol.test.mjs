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
  assert.equal(init.packet.length, 14769);
  assert.equal(response.respPacket.length, 3196);
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
    a.codec.encodeUTF8('ECP-INIT-v2'),
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
