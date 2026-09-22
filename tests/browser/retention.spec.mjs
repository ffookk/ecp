import { test, expect } from '@playwright/test';

const passphrase = 'synthetic-retention-vault-passphrase';

async function unlock(page, create = false) {
  await expect(page.locator('#vault-submit')).toHaveText(
    create ? 'Create vault' : 'Unlock',
  );
  await page.locator('#vault-password').fill(passphrase);
  if (create) await page.locator('#vault-confirm').fill(passphrase);
  await page.locator('#vault-submit').click();
  await expect(page.locator('#app-root')).toBeVisible();
}

async function openVault(page, create = true) {
  await page.addInitScript(() => {
    // Test data never reaches the operating system clipboard.
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
  await unlock(page, create);
}

async function identity(page) {
  return page.evaluate(async () => {
    const id = await import('/identity.js');
    const { formatEnvelope } = await import('/codec.js');
    const bytes = id.serializeIdentityPublic(await id.getLocalIdentity());
    return {
      fingerprint: id.calculateFingerprint(bytes),
      envelope: formatEnvelope(bytes),
    };
  });
}

async function addPeer(page, peer, name) {
  await page.evaluate((value) => {
    window.testClipboard = value;
  }, peer.envelope);
  await page.locator('#btn-add-contact').click();
  await page.locator('#new-alias-input').fill(name);
  await page.locator('#verified-fp-input').fill(peer.fingerprint);
  await page.locator('#btn-confirm-add').click();
  await selectPeer(page, name);
}

async function selectPeer(page, name) {
  await page.locator('#contacts-list').getByText(name, { exact: true }).click();
  await expect(page.locator('#chat-title')).toHaveText(name);
}

async function relay(sender, receiver) {
  const packet = await sender.evaluate(() => window.testClipboard);
  await receiver.evaluate((value) => {
    window.testClipboard = value;
  }, packet);
  await receiver.locator('#btn-read-clipboard').click();
}

async function pair(browser) {
  const contexts = await Promise.all([
    browser.newContext(),
    browser.newContext(),
  ]);
  const [a, b] = await Promise.all(
    contexts.map((context) => context.newPage()),
  );
  for (const page of [a, b]) await openVault(page);
  const aId = await identity(a),
    bId = await identity(b);
  await addPeer(a, bId, 'Synthetic Bob');
  await addPeer(b, aId, 'Synthetic Alice');
  await a.locator('#btn-start-session').click();
  await expect(a.locator('#chat-status-text')).toHaveText('Awaiting RESP');
  await relay(a, b);
  await expect(b.locator('#chat-status-text')).toHaveText(
    'Channel Established',
  );
  await relay(b, a);
  await expect(a.locator('#chat-status-text')).toHaveText(
    'Channel Established',
  );
  return { a, b, aId, bId, contexts };
}

async function send(page, text) {
  await page.locator('#chat-input').fill(text);
  await page.locator('#chat-form button[type=submit]').click();
  await expect(page.locator('#chat-messages')).toContainText(text);
}

async function savedMessages(page) {
  return page.evaluate(async () =>
    (await import('/storage.js')).DB.getAll('messages'),
  );
}

async function historySettings(page) {
  await page.locator('#btn-peer-menu').click();
  await page.locator('#btn-history-settings').click();
  await expect(page.locator('#save-history')).toBeVisible();
}

async function setSaving(page, enabled) {
  await historySettings(page);
  await page.locator('#save-history').setChecked(enabled);
  await page.locator('#btn-save-history').click();
  await expect(page.locator('#modal-overlay')).toBeHidden();
  await expect(page.locator('#history-status')).toContainText(
    enabled ? 'Saving new messages' : 'New messages stay in this tab only',
  );
}

test('default temporary history is page-local and disappears on reload and lock', async ({
  browser,
}) => {
  const { a, b, contexts } = await pair(browser);
  try {
    await expect(a.locator('#history-status')).toContainText(
      '100-message / 8 MiB',
    );
    await historySettings(a);
    await expect(a.locator('#save-history')).not.toBeChecked();
    await a.locator('#btn-cancel-history').click();
    await send(a, 'Synthetic temporary secret');
    await relay(a, b);
    await expect(b.locator('#chat-messages')).toContainText(
      'Synthetic temporary secret',
    );
    expect(await savedMessages(a)).toEqual([]);
    expect(await savedMessages(b)).toEqual([]);

    const otherTab = await contexts[0].newPage();
    await openVault(otherTab, false);
    await selectPeer(otherTab, 'Synthetic Bob');
    await expect(otherTab.locator('#chat-messages')).toBeEmpty();

    await a.reload();
    await unlock(a);
    await selectPeer(a, 'Synthetic Bob');
    await expect(a.locator('#chat-messages')).toBeEmpty();
    await b.evaluate(async () => (await import('/storage.js')).Vault.lock());
    await unlock(b);
    await selectPeer(b, 'Synthetic Alice');
    await expect(b.locator('#chat-messages')).toBeEmpty();
    await send(a, 'Synthetic channel still works');
    await relay(a, b);
    await expect(b.locator('#chat-messages')).toContainText(
      'Synthetic channel still works',
    );
    expect(await savedMessages(a)).toEqual([]);
    expect(await savedMessages(b)).toEqual([]);
  } finally {
    for (const context of contexts) await context.close();
  }
});

test('explicit saving affects only future messages and clear removes saved plus cross-tab temporary history', async ({
  browser,
}) => {
  const { a, b, bId, contexts } = await pair(browser);
  try {
    await send(a, 'Synthetic earlier temporary');
    await relay(a, b);
    await setSaving(a, true);
    await send(a, 'Synthetic opted-in saved');
    await relay(a, b);
    expect((await savedMessages(a)).map((message) => message.text)).toEqual([
      'Synthetic opted-in saved',
    ]);
    expect(await savedMessages(b)).toEqual([]);
    await setSaving(a, false);
    await send(a, 'Synthetic later temporary');
    await relay(a, b);
    expect((await savedMessages(a)).map((message) => message.text)).toEqual([
      'Synthetic opted-in saved',
    ]);

    await a.reload();
    await unlock(a);
    await selectPeer(a, 'Synthetic Bob');
    await expect(a.locator('#chat-messages')).toContainText(
      'Synthetic opted-in saved',
    );
    await expect(a.locator('#chat-messages')).not.toContainText(
      'Synthetic earlier temporary',
    );
    await expect(a.locator('#chat-messages')).not.toContainText(
      'Synthetic later temporary',
    );

    const otherTab = await contexts[0].newPage();
    await openVault(otherTab, false);
    await selectPeer(otherTab, 'Synthetic Bob');
    await send(otherTab, 'Synthetic other-tab temporary');
    const before = await a.evaluate(async (fp) => {
      const { DB } = await import('/storage.js');
      await DB.put('messages', {
        id: 'older-channel-history',
        contactFp: fp,
        conversationId: 'synthetic-old-conversation',
        isMe: true,
        text: 'Synthetic older channel',
        timestamp: 0,
      });
      return {
        session: await DB.get('sessions', fp),
        contact: await DB.get('contacts', fp),
        replays: await DB.getAll('replays'),
      };
    }, bId.fingerprint);
    expect(await savedMessages(a)).toHaveLength(2);
    await historySettings(a);
    await expect(a.locator('#save-history')).not.toBeChecked();
    a.once('dialog', (dialog) => dialog.accept());
    await a.locator('#btn-clear-history').click();
    await expect(a.locator('#modal-overlay')).toBeHidden();
    await expect(a.locator('#chat-messages')).toBeEmpty();
    await expect(otherTab.locator('#chat-messages')).toBeEmpty();
    expect(await savedMessages(a)).toEqual([]);
    const after = await a.evaluate(async (fp) => {
      const { DB } = await import('/storage.js');
      return {
        session: await DB.get('sessions', fp),
        contact: await DB.get('contacts', fp),
        replays: await DB.getAll('replays'),
      };
    }, bId.fingerprint);
    expect(after).toEqual(before);
    await expect(a.locator('#chat-status-text')).toHaveText(
      'Channel Established',
    );
  } finally {
    for (const context of contexts) await context.close();
  }
});

test('history preference saves expire when a different peer is selected', async ({
  browser,
}) => {
  const { a, bId, contexts } = await pair(browser);
  try {
    // A second synthetic contact is enough to exercise the real selection path.
    const secondFp = await a.evaluate(async () => {
      const { DB } = await import('/storage.js');
      const {
        getLocalIdentity,
        serializeIdentityPublic,
        calculateFingerprint,
      } = await import('/identity.js');
      const { encodeBase64URL } = await import('/crypto.js');
      const bytes = serializeIdentityPublic(await getLocalIdentity());
      const fp = calculateFingerprint(bytes);
      await DB.put('contacts', {
        fingerprint: fp,
        bundle: encodeBase64URL(bytes),
        name: 'Synthetic Other Contact',
        verified: true,
        archived: false,
        lastReadTimestamp: 0,
      });
      return fp;
    });
    await historySettings(a);
    await a.locator('#save-history').check();
    await a.evaluate(async (fp) => {
      const { DB } = await import('/storage.js');
      const get = DB.get.bind(DB);
      let delayed = false;
      DB.get = async (...args) => {
        const result = await get(...args);
        if (!delayed && args[0] === 'contacts' && args[1] === fp) {
          delayed = true;
          window.preferenceReadDelayed = true;
          await new Promise((resolve) => {
            window.releasePreferenceRead = resolve;
          });
        }
        return result;
      };
      const button = document.querySelector('#btn-save-history'),
        original = button.onclick;
      button.onclick = function (event) {
        const result = original.call(this, event);
        window.preferenceSave = Promise.resolve(result);
        return result;
      };
    }, bId.fingerprint);
    await a.locator('#btn-save-history').click();
    await expect
      .poll(() => a.evaluate(() => window.preferenceReadDelayed))
      .toBe(true);
    await a.evaluate((fp) => {
      location.hash = `#${fp}`;
    }, secondFp);
    await expect(a.locator('#modal-overlay')).toBeHidden();
    await a.evaluate(async () => {
      window.releasePreferenceRead();
      await window.preferenceSave;
    });
    await expect(a.locator('#chat-title')).toHaveText(
      'Synthetic Other Contact',
    );
    const contact = await a.evaluate(
      async (fp) => (await import('/storage.js')).DB.get('contacts', fp),
      bId.fingerprint,
    );
    expect(contact.saveHistory).not.toBe(true);
  } finally {
    for (const context of contexts) await context.close();
  }
});

test('temporary cache enforces count and data limits, peer isolation and stale-result rejection', async ({
  page,
}) => {
  await openVault(page);
  const result = await page.evaluate(async () => {
    const { TransientHistory, TRANSIENT_BYTE_LIMIT } =
      await import('/history.js');
    const make = (id, contactFp = 'a', text = id) => ({
      id,
      contactFp,
      conversationId: 'channel',
      isMe: true,
      text,
      timestamp: 0,
    });
    const cache = new TransientHistory();
    for (let index = 0; index < 101; index++) cache.add(make(String(index)));
    const counted = cache.forConversation('a', 'channel');
    cache.clear();
    const payload = 'x'.repeat(1024 * 1024);
    for (let index = 0; index < 5; index++)
      cache.add(make(String(index), 'a', payload));
    const bounded = cache.forConversation('a', 'channel');
    const bytes = bounded.reduce(
      (sum, message) =>
        sum +
        2 *
          (message.text.length +
            message.id.length +
            message.contactFp.length +
            message.conversationId.length) +
        16,
      0,
    );
    cache.add(make('too-large', 'a', 'x'.repeat(TRANSIENT_BYTE_LIMIT)));
    const oversizedRejected = !cache
      .forConversation('a', 'channel')
      .some((message) => message.id === 'too-large');
    cache.clear();
    cache.add(make('a-existing'));
    cache.add(make('b-existing', 'b'));
    const remember = cache.captureWrite();
    cache.clearPeer('a');
    remember(make('a-stale'));
    remember(make('b-still-current', 'b'));
    const isolated = {
      a: cache.forConversation('a', 'channel'),
      b: cache.forConversation('b', 'channel').map((message) => message.id),
    };
    const beforeLock = cache.captureWrite();
    cache.clear();
    beforeLock(make('b-stale-after-lock', 'b'));
    return {
      count: counted.length,
      first: counted[0].id,
      bounded: bounded.length,
      bytes,
      limit: TRANSIENT_BYTE_LIMIT,
      oversizedRejected,
      isolated,
      afterLock: cache.forConversation('b', 'channel'),
    };
  });
  expect(result.count).toBe(100);
  expect(result.first).toBe('1');
  expect(result.bounded).toBe(3);
  expect(result.bytes).toBeLessThanOrEqual(result.limit);
  expect(result.oversizedRejected).toBe(true);
  expect(result.isolated).toEqual({
    a: [],
    b: ['b-existing', 'b-still-current'],
  });
  expect(result.afterLock).toEqual([]);
});
