import { test, expect } from '@playwright/test';

const passphrase = 'synthetic-test-vault-passphrase';
async function openVault(page, create = true) {
  await page.addInitScript(() => {
    // Keep synthetic packets inside this isolated page, off the OS clipboard.
    window.testClipboard = '';
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        readText: async () => window.testClipboard,
        writeText: async (value) => {
          window.testClipboard = value;
        },
      },
    });
  });
  await page.goto('/');
  await expect(page.locator('#vault-submit')).toHaveText(
    create ? 'Create vault' : 'Unlock',
  );
  await page.locator('#vault-password').fill(passphrase);
  if (create) await page.locator('#vault-confirm').fill(passphrase);
  await page.locator('#vault-submit').click();
  await expect(page.locator('#app-root')).toBeVisible();
}
async function identity(page) {
  return page.evaluate(async () => {
    const identity = await import('/identity.js');
    const codec = await import('/codec.js');
    const bytes = identity.serializeIdentityPublic(
      await identity.getLocalIdentity(),
    );
    return {
      fingerprint: identity.calculateFingerprint(bytes),
      envelope: codec.formatEnvelope(bytes),
    };
  });
}
async function addPeer(page, peer, alias) {
  await page.evaluate((envelope) => {
    window.testClipboard = envelope;
  }, peer.envelope);
  await page.locator('#btn-add-contact').click();
  await page.locator('#new-alias-input').fill(alias);
  await page.locator('#verified-fp-input').fill(peer.fingerprint);
  await page.locator('#btn-confirm-add').click();
  await expect(page.locator('#contacts-list')).toContainText(alias);
  await page.getByText(alias, { exact: true }).click();
}
async function copyPacket(from, to) {
  const packet = await from.evaluate(() => window.testClipboard);
  await to.evaluate((packet) => {
    window.testClipboard = packet;
  }, packet);
  await to.locator('#btn-read-clipboard').click();
}

test('vault, independently confirmed contacts, handshake, ratchet and lock UI', async ({
  browser,
}) => {
  const aContext = await browser.newContext();
  const bContext = await browser.newContext();
  const alice = await aContext.newPage();
  const bob = await bContext.newPage();
  const errors = [];
  const remoteRequests = [];
  for (const page of [alice, bob]) {
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => {
      if (!request.url().startsWith('http://127.0.0.1:4173/'))
        remoteRequests.push(request.url());
    });
  }
  try {
    await openVault(alice);
    await openVault(bob);
    const aId = await identity(alice);
    const bId = await identity(bob);
    await addPeer(alice, bId, 'Synthetic Bob');
    await addPeer(bob, aId, 'Synthetic Alice');
    await expect(
      alice.locator('#chat-form button[type=submit]'),
    ).toBeDisabled();
    await alice.locator('#btn-start-session').click();
    await expect(alice.locator('#chat-status-text')).toHaveText(
      'Awaiting RESP',
    );
    await copyPacket(alice, bob);
    await expect(bob.locator('#chat-status-text')).toHaveText(
      'Channel Established',
    );
    await copyPacket(bob, alice);
    await expect(alice.locator('#chat-status-text')).toHaveText(
      'Channel Established',
    );
    for (const [sender, receiver, text] of [
      [alice, bob, 'synthetic A1'],
      [bob, alice, 'synthetic B1'],
      [bob, alice, 'synthetic B2'],
      [alice, bob, 'synthetic A2'],
      [alice, bob, 'synthetic A3'],
    ]) {
      await sender.locator('#chat-input').fill(text);
      await sender.locator('#chat-form button[type=submit]').click();
      await expect(sender.locator('#chat-messages')).toContainText(text);
      await copyPacket(sender, receiver);
      await expect(receiver.locator('#chat-messages')).toContainText(text);
    }
    // A second real browser page shares IndexedDB and the origin's Web Locks.
    const second = await aContext.newPage();
    await openVault(second, false);
    const send = (page, text) =>
      page.evaluate(
        async ({ fp, text }) => {
          const { EncryptMessage } = await import('/ratchet.js');
          const result = await EncryptMessage(fp, text);
          return Array.from(result.packet);
        },
        { fp: bId.fingerprint, text },
      );
    const packets = await Promise.all([
      send(alice, 'parallel-one'),
      send(second, 'parallel-two'),
    ]);
    const decoded = [];
    for (const packet of packets)
      decoded.push(
        await bob.evaluate(async (data) => {
          const { DecryptMessage } = await import('/ratchet.js');
          return (await DecryptMessage(new Uint8Array(data))).plaintext;
        }, packet),
      );
    expect(decoded.sort()).toEqual(['parallel-one', 'parallel-two']);
    const counters = packets.map((bytes) =>
      new DataView(new Uint8Array(bytes).buffer).getUint32(3200),
    );
    expect(new Set(counters).size).toBe(2);
    await alice.locator('#btn-global-settings').click();
    await alice.locator('#btn-lock-vault').click();
    await expect(alice.locator('#vault-screen')).toBeVisible();
    await expect(second.locator('#vault-screen')).toBeVisible();
    await expect(alice.locator('#chat-messages')).toBeEmpty();
    await expect(alice.locator('#chat-input')).toHaveValue('');
    expect(errors).toEqual([]);
    expect(remoteRequests).toEqual([]);
  } finally {
    await aContext.close();
    await bContext.close();
  }
});

test('wrong vault passphrase fails visibly', async ({ page }) => {
  await openVault(page);
  await page.locator('#btn-global-settings').click();
  await page.locator('#btn-lock-vault').click();
  await expect(page.locator('#vault-submit')).toHaveText('Unlock');
  await page.locator('#vault-password').fill('wrong-synthetic-passphrase');
  await page.locator('#vault-submit').click();
  await expect(page.locator('#vault-error')).not.toBeEmpty();
  await expect(page.locator('#app-root')).toBeHidden();
});

test('contact confirmation rejects a mismatched full fingerprint', async ({
  page,
}) => {
  await openVault(page);
  const peer = await page.evaluate(async () => {
    const { serializeIdentityPublic, calculateFingerprint } =
      await import('/identity.js');
    const { formatEnvelope } = await import('/codec.js');
    const crypto = await import('/crypto.js');
    const bytes = serializeIdentityPublic({
      ecPk: crypto.keygenEd25519().publicKey,
      dsaPk: crypto.keygenMLDSA87().publicKey,
      dhPk: crypto.keygenX25519().publicKey,
      kemPk: crypto.keygenMLKEM1024().publicKey,
    });
    return {
      envelope: formatEnvelope(bytes),
      fingerprint: calculateFingerprint(bytes),
    };
  });
  await page.evaluate((value) => {
    window.testClipboard = value;
  }, peer.envelope);
  await page.locator('#btn-add-contact').click();
  await page.locator('#new-alias-input').fill('Unconfirmed synthetic peer');
  await page
    .locator('#verified-fp-input')
    .fill('not-the-confirmed-fingerprint');
  await page.locator('#btn-confirm-add').click();
  await expect(page.locator('#contacts-list')).not.toContainText(
    'Unconfirmed synthetic peer',
  );
  expect(
    await page.evaluate(async () =>
      (await import('/storage.js')).DB.getAll('contacts'),
    ),
  ).toEqual([]);
  await page.locator('#verified-fp-input').fill(peer.fingerprint);
  await page.locator('#btn-confirm-add').click();
  await expect(page.locator('#contacts-list')).toContainText(
    'Unconfirmed synthetic peer',
  );
});

test('vault deletion clears the UI and creates a fresh identity', async ({
  page,
}) => {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await openVault(page);
  const before = await identity(page);
  page.on('dialog', (dialog) => dialog.accept());
  await page.locator('#btn-global-settings').click();
  await page.locator('#btn-destroy-vault').click();
  await expect(page.locator('#vault-submit')).toHaveText('Create vault');
  await expect(page.locator('#app-root')).toBeHidden();
  await page.locator('#vault-password').fill(passphrase);
  await page.locator('#vault-confirm').fill(passphrase);
  await page.locator('#vault-submit').click();
  await expect(page.locator('#app-root')).toBeVisible();
  expect((await identity(page)).fingerprint).not.toBe(before.fingerprint);
  expect(errors).toEqual([]);
});

test('delayed history and attachment callbacks stay bound to the selected recipient', async ({
  browser,
}) => {
  const contexts = await Promise.all([
    browser.newContext(),
    browser.newContext(),
    browser.newContext(),
  ]);
  try {
    const [alice, bob, charlie] = await Promise.all(
      contexts.map((context) => context.newPage()),
    );
    for (const page of [alice, bob, charlie]) await openVault(page);
    const aId = await identity(alice),
      bId = await identity(bob),
      cId = await identity(charlie);
    for (const [peer, peerId, alias] of [
      [bob, bId, 'Synthetic Bob'],
      [charlie, cId, 'Synthetic Charlie'],
    ]) {
      await addPeer(alice, peerId, alias);
      await addPeer(peer, aId, 'Synthetic Alice');
      await alice.locator('#btn-start-session').click();
      await expect(alice.locator('#chat-status-text')).toHaveText(
        'Awaiting RESP',
      );
      await copyPacket(alice, peer);
      await expect(peer.locator('#chat-status-text')).toHaveText(
        'Channel Established',
      );
      await copyPacket(peer, alice);
      await expect(alice.locator('#chat-status-text')).toHaveText(
        'Channel Established',
      );
      const text = `History belonging to ${alias}`;
      await alice.locator('#chat-input').fill(text);
      await alice.locator('#chat-form button[type=submit]').click();
      await expect(alice.locator('#chat-messages')).toContainText(text);
    }
    await alice.evaluate(async (fp) => {
      const { DB } = await import('/storage.js');
      const session = await DB.get('sessions', fp);
      const original = DB.getAllByIndex.bind(DB);
      let delayed = false;
      DB.getAllByIndex = async (...args) => {
        const rows = await original(...args);
        if (
          !delayed &&
          args[0] === 'messages' &&
          args[2] === session.conversationId
        ) {
          delayed = true;
          window.historyQueryDelayed = true;
          await new Promise((resolve) => {
            window.releaseHistory = resolve;
          });
        }
        return rows;
      };
    }, bId.fingerprint);
    await alice.getByText('Synthetic Bob', { exact: true }).click();
    await expect
      .poll(() => alice.evaluate(() => window.historyQueryDelayed))
      .toBe(true);
    await alice.getByText('Synthetic Charlie', { exact: true }).click();
    await expect(alice.locator('#chat-messages')).toContainText(
      'History belonging to Synthetic Charlie',
    );
    await alice.evaluate(() => window.releaseHistory());
    await alice.evaluate(
      () => new Promise((resolve) => requestAnimationFrame(resolve)),
    );
    await expect(alice.locator('#chat-title')).toHaveText('Synthetic Charlie');
    await expect(alice.locator('#chat-messages')).not.toContainText(
      'History belonging to Synthetic Bob',
    );

    await alice.getByText('Synthetic Bob', { exact: true }).click();
    await expect(alice.locator('#chat-messages')).toContainText(
      'History belonging to Synthetic Bob',
    );
    await alice.locator('#chat-input').fill('Draft intended only for Bob');
    await alice.evaluate(() => {
      window.FileReader = class {
        result = null;
        readAsDataURL() {
          window.deliverPendingMedia = () => {
            this.result = 'data:image/png;base64,c3ludGhldGljLW9ubHk=';
            this.onload?.({ target: this });
          };
        }
        abort() {
          this.onabort?.();
        }
      };
    });
    await alice
      .locator('#media-input')
      .setInputFiles({
        name: 'synthetic.png',
        mimeType: 'image/png',
        buffer: Buffer.from('synthetic-only'),
      });
    await alice.getByText('Synthetic Charlie', { exact: true }).click();
    await expect(alice.locator('#chat-title')).toHaveText('Synthetic Charlie');
    await expect(alice.locator('#chat-input')).toHaveValue('');
    const readState = () =>
      alice.evaluate(async () => {
        const { DB } = await import('/storage.js');
        return {
          sessions: await DB.getAll('sessions'),
          messages: await DB.getAll('messages'),
        };
      });
    const before = await readState();
    await alice.evaluate(async () => {
      window.deliverPendingMedia();
      await navigator.locks.request('ECP_SECURE_DB_v2:state', () => {});
    });
    expect(await readState()).toEqual(before);
  } finally {
    for (const context of contexts) await context.close();
  }
});
