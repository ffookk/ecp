import test from 'node:test';
import assert from 'node:assert/strict';
import { createProtocolLab } from './helpers/protocol-peers.mjs';

const hex = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const utf8 = (value) => new TextEncoder().encode(value);

test('AES-256-GCM-SIV matches RFC 8452 C.2 known-answer vectors', async (t) => {
  const { peer } = await createProtocolLab(t);
  const { cryptography: c } = await peer();
  const key = hex('01' + '00'.repeat(31));
  const nonce = hex('03' + '00'.repeat(11));
  // https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C.2
  const vectors = [
    ['', '', '07f5f4169bbf55a8400cd47ea6fd400f'],
    [
      '0100000000000000',
      '',
      'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28',
    ],
    [
      '0200000000000000',
      '01',
      '1de22967237a813291213f267e3b452f02d01ae33e4ec854',
    ],
    [
      '0200000000000000000000000000000003000000000000000000000000000000',
      '01',
      '07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc',
    ],
  ];
  for (const [plaintext, aad, expected] of vectors) {
    const ciphertext = c.encryptGCMSIV(key, nonce, hex(plaintext), hex(aad));
    assert.deepEqual(ciphertext, hex(expected));
    assert.deepEqual(
      c.decryptGCMSIV(key, nonce, ciphertext, hex(aad)),
      hex(plaintext),
    );
  }
});

test('sealed packets require AES-256 keys, fresh nonces and authentic nonce/AAD/ciphertext/tag', async (t) => {
  const { peer } = await createProtocolLab(t);
  const { cryptography: c } = await peer();
  const key = c.getRandomBytes(32),
    plain = utf8('synthetic secret'),
    aad = utf8('context');
  const sealed = c.encryptPacket(key, plain, aad);
  const second = c.encryptPacket(key, plain, aad);
  assert.equal(sealed.length, plain.length + 28);
  assert.notDeepEqual(sealed.slice(0, 12), second.slice(0, 12));
  assert.deepEqual(c.decryptPacket(key, sealed, aad), plain);
  for (const index of [0, 11, 12, sealed.length - 1]) {
    const modified = sealed.slice();
    modified[index] ^= 1;
    assert.throws(() => c.decryptPacket(key, modified, aad));
  }
  assert.throws(() => c.decryptPacket(key, sealed, utf8('other context')));
  assert.throws(() => c.decryptPacket(c.getRandomBytes(32), sealed, aad));
  for (const length of [0, 12, 16, 27])
    assert.throws(
      () => c.decryptPacket(key, new Uint8Array(length), aad),
      /Truncated/,
    );
  for (const length of [0, 16, 24, 31, 33]) {
    const wrong = new Uint8Array(length);
    assert.throws(() => c.encryptPacket(wrong, plain, aad), /32-byte/);
    assert.throws(() => c.decryptPacket(wrong, sealed, aad), /32-byte/);
  }
  t.mock.method(crypto, 'getRandomValues', () => {
    throw new Error('RNG unavailable');
  });
  assert.throws(() => c.encryptPacket(key, plain, aad), /RNG unavailable/);
});

test('repeated nonce GCM-SIV does not reproduce the GCM plaintext-XOR leakage', async (t) => {
  const { peer } = await createProtocolLab(t);
  const { cryptography: c } = await peer();
  const key = c.getRandomBytes(32),
    nonce = c.getRandomBytes(12),
    aad = utf8('same context');
  const left = utf8('synthetic branch A'),
    right = utf8('synthetic branch B');
  const encryptedLeft = c.encryptGCMSIV(key, nonce, left, aad);
  const encryptedRight = c.encryptGCMSIV(key, nonce, right, aad);
  assert.equal(
    left.every(
      (v, i) => (v ^ right[i]) === (encryptedLeft[i] ^ encryptedRight[i]),
    ),
    false,
  );
  assert.deepEqual(c.decryptGCMSIV(key, nonce, encryptedLeft, aad), left);
  assert.deepEqual(c.decryptGCMSIV(key, nonce, encryptedRight, aad), right);
  // This equality leakage remains when key, nonce, AAD and plaintext all repeat.
  assert.deepEqual(c.encryptGCMSIV(key, nonce, left, aad), encryptedLeft);
  const forged = encryptedRight.slice();
  forged.set(encryptedLeft.subarray(-16), forged.length - 16);
  assert.throws(() => c.decryptGCMSIV(key, nonce, forged, aad));
});
