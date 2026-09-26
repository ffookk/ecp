import { test, expect } from '@playwright/test';

const passphrase = 'synthetic-lifecycle-vault-passphrase';

async function openVault(page) {
  await page.addInitScript(() => {
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
  await page.locator('#vault-password').fill(passphrase);
  await page.locator('#vault-confirm').fill(passphrase);
  await page.locator('#vault-submit').click();
  await expect(page.locator('#app-root')).toBeVisible();
}

async function lockAndUnlock(page) {
  await page.evaluate(async () => (await import('/storage.js')).Vault.lock());
  await expect(page.locator('#vault-submit')).toHaveText('Unlock');
  await page.locator('#vault-password').fill(passphrase);
  await page.locator('#vault-submit').click();
  await expect(page.locator('#app-root')).toBeVisible();
}

async function syntheticIdentity(page) {
  return page.evaluate(async () => {
    const identity = await import('/identity.js');
    const { formatEnvelope } = await import('/codec.js');
    const c = await import('/crypto.js');
    const bytes = identity.serializeIdentityPublic({
      ecPk: c.keygenEd25519().publicKey,
      dsaPk: c.keygenMLDSA87().publicKey,
      dhPk: c.keygenX25519().publicKey,
      kemPk: c.keygenMLKEM1024().publicKey,
    });
    return {
      fingerprint: identity.calculateFingerprint(bytes),
      bundle: c.encodeBase64URL(bytes),
      envelope: formatEnvelope(bytes),
    };
  });
}

async function seedPeers(page, legacy = false) {
  const peers = [await syntheticIdentity(page), await syntheticIdentity(page)];
  await page.evaluate(
    async ({ peers, legacy }) => {
      const { DB } = await import('/storage.js');
      for (const [index, peer] of peers.entries()) {
        await DB.put('contacts', {
          fingerprint: peer.fingerprint,
          bundle: peer.bundle,
          name: index ? 'Synthetic Peer B' : 'Synthetic Peer A',
          verified: true,
          archived: false,
          lastReadTimestamp: 0,
        });
      }
      if (legacy) {
        const fp = peers[0].fingerprint,
          conversationId = 'synthetic-v2-conversation';
        await DB.putMany([
          [
            'sessions',
            {
              contactFp: fp,
              version: 2,
              conversationId,
              peerIdentity: peers[0].bundle,
              DHs: {
                sk: new Uint8Array(32).fill(1),
                pk: new Uint8Array(32).fill(2),
              },
              RK: new Uint8Array(32).fill(3),
              CKs: new Uint8Array(32).fill(4),
              Ns: 1,
              Nr: 0,
              PN: 0,
              state: 'ESTABLISHED',
            },
          ],
          [
            'messages',
            {
              id: 'synthetic-v2-message',
              contactFp: fp,
              conversationId,
              isMe: true,
              text: 'Synthetic retained v2 history',
              timestamp: 1234,
            },
          ],
        ]);
      }
    },
    { peers, legacy },
  );
  await page.locator('#btn-toggle-archived').click();
  await expect(page.locator('#contacts-list')).toContainText(
    'Synthetic Peer B',
  );
  await page
    .locator('#contacts-list')
    .getByText('Synthetic Peer A', { exact: true })
    .click();
  await expect(page.locator('#chat-title')).toHaveText('Synthetic Peer A');
  return peers;
}

// Observe completion of the actual application event handler, avoiding sleeps
// and avoiding application-only test hooks in production source.
async function observeClick(page, selector) {
  await page.evaluate((selector) => {
    const button = document.querySelector(selector),
      original = button.onclick;
    button.onclick = function (event) {
      const result = original.call(this, event);
      window.observedAction = Promise.resolve(result);
      return result;
    };
  }, selector);
}

async function delayContactRead(page, fingerprint) {
  await page.evaluate(async (fingerprint) => {
    const { DB } = await import('/storage.js');
    const original = DB.get.bind(DB);
    let delayed = false;
    DB.get = async (...args) => {
      const result = await original(...args);
      if (!delayed && args[0] === 'contacts' && args[1] === fingerprint) {
        delayed = true;
        window.contactReadDelayed = true;
        await new Promise((resolve) => {
          window.releaseContactRead = resolve;
        });
      }
      return result;
    };
  }, fingerprint);
}

async function peerNames(page) {
  return page.evaluate(async () =>
    (await (await import('/storage.js')).DB.getAll('contacts'))
      .map((c) => c.name)
      .sort(),
  );
}

async function readPeerState(page, fingerprint) {
  return page.evaluate(async (fp) => {
    const { DB } = await import('/storage.js');
    return {
      contact: await DB.get('contacts', fp),
      session: await DB.get('sessions', fp),
      messages: await DB.getAllByIndex('messages', 'contactFp', fp),
    };
  }, fingerprint);
}

async function queueConfirmedAction(page, selector) {
  await page.evaluate(() => {
    window.heldStateLock = navigator.locks.request(
      'ECP_SECURE_DB_v2:state',
      () =>
        new Promise((resolve) => {
          window.stateLockHeld = true;
          window.releaseStateLock = resolve;
        }),
    );
  });
  await expect.poll(() => page.evaluate(() => window.stateLockHeld)).toBe(true);
  await observeClick(page, selector);
  await page.locator(selector).click();
  await expect
    .poll(() =>
      page.evaluate(async () =>
        (await navigator.locks.query()).pending.some(
          (lock) => lock.name === 'ECP_SECURE_DB_v2:state',
        ),
      ),
    )
    .toBe(true);
}

async function releaseConfirmedAction(page) {
  await page.evaluate(async () => {
    window.releaseStateLock();
    await window.heldStateLock;
    await window.observedAction;
  });
}

test('a delayed initial rename read cannot open a modal for the previously selected peer', async ({
  page,
}) => {
  await openVault(page);
  const [a] = await seedPeers(page);
  await delayContactRead(page, a.fingerprint);
  await observeClick(page, '#btn-rename-contact');
  await page.locator('#btn-peer-menu').click();
  await page.locator('#btn-rename-contact').click();
  await expect
    .poll(() => page.evaluate(() => window.contactReadDelayed))
    .toBe(true);
  await page
    .locator('#contacts-list')
    .getByText('Synthetic Peer B', { exact: true })
    .click();
  await expect(page.locator('#chat-title')).toHaveText('Synthetic Peer B');
  await page.evaluate(async () => {
    window.releaseContactRead();
    await window.observedAction;
  });
  await expect(page.locator('#modal-overlay')).toBeHidden();
  await expect(page.locator('#rename-val')).toHaveCount(0);
  await expect(page.locator('#chat-title')).toHaveText('Synthetic Peer B');
  expect(await peerNames(page)).toEqual([
    'Synthetic Peer A',
    'Synthetic Peer B',
  ]);
});

test('a rename save waiting on its contact read cannot write or relabel after selection changes', async ({
  page,
}) => {
  await openVault(page);
  const [a, b] = await seedPeers(page);
  await page.locator('#btn-peer-menu').click();
  await page.locator('#btn-rename-contact').click();
  await expect(page.locator('#rename-val')).toHaveValue('Synthetic Peer A');
  await page.locator('#rename-val').fill('Stale renamed alias');
  await delayContactRead(page, a.fingerprint);
  await observeClick(page, '#btn-save');
  await page.locator('#btn-save').click();
  await expect
    .poll(() => page.evaluate(() => window.contactReadDelayed))
    .toBe(true);
  // Hash navigation is a real selection path available while a modal is open.
  // B's last-read write queues behind A's paused save, so release only after
  // the route has invalidated the modal, then wait for B's completed selection.
  await page.evaluate((fp) => {
    location.hash = `#${fp}`;
  }, b.fingerprint);
  await expect(page.locator('#modal-overlay')).toBeHidden();
  await page.evaluate(async () => {
    window.releaseContactRead();
    await window.observedAction;
  });
  await expect(page.locator('#chat-title')).toHaveText('Synthetic Peer B');
  expect(await peerNames(page)).toEqual([
    'Synthetic Peer A',
    'Synthetic Peer B',
  ]);
  await expect(page.locator('#contacts-list')).not.toContainText(
    'Stale renamed alias',
  );
});

test('a queued add-contact save expires across vault lock and unlock', async ({
  page,
}) => {
  await openVault(page);
  const peer = await syntheticIdentity(page);
  await page.evaluate((value) => {
    window.testClipboard = value;
  }, peer.envelope);
  await page.locator('#btn-add-contact').click();
  await page.locator('#new-alias-input').fill('Expired synthetic peer');
  await page.locator('#verified-fp-input').fill(peer.fingerprint);
  await page.evaluate(async () => {
    window.heldStateLock = navigator.locks.request(
      'ECP_SECURE_DB_v2:state',
      () =>
        new Promise((resolve) => {
          window.stateLockHeld = true;
          window.releaseStateLock = resolve;
        }),
    );
  });
  await expect.poll(() => page.evaluate(() => window.stateLockHeld)).toBe(true);
  await observeClick(page, '#btn-confirm-add');
  await page.locator('#btn-confirm-add').click();
  await expect
    .poll(() =>
      page.evaluate(async () =>
        (await navigator.locks.query()).pending.some(
          (lock) => lock.name === 'ECP_SECURE_DB_v2:state',
        ),
      ),
    )
    .toBe(true);
  await lockAndUnlock(page);
  await page.evaluate(async () => {
    window.releaseStateLock();
    await window.heldStateLock;
    await window.observedAction;
  });
  expect(await peerNames(page)).toEqual([]);
  await expect(page.locator('#modal-overlay')).toBeHidden();
  await expect(page.locator('#contacts-list')).not.toContainText(
    'Expired synthetic peer',
  );
});

test('a delayed clipboard identity read cannot reopen an import after lock and unlock', async ({
  page,
}) => {
  await openVault(page);
  const peer = await syntheticIdentity(page);
  await page.evaluate((value) => {
    navigator.clipboard.readText = async () => {
      window.clipboardReadDelayed = true;
      await new Promise((resolve) => {
        window.releaseClipboardRead = resolve;
      });
      return value;
    };
  }, peer.envelope);
  await observeClick(page, '#btn-add-contact');
  await page.locator('#btn-add-contact').click();
  await expect
    .poll(() => page.evaluate(() => window.clipboardReadDelayed))
    .toBe(true);
  await lockAndUnlock(page);
  await page.evaluate(async () => {
    window.releaseClipboardRead();
    await window.observedAction;
  });
  await expect(page.locator('#modal-overlay')).toBeHidden();
  await expect(page.locator('#new-alias-input')).toHaveCount(0);
  expect(await peerNames(page)).toEqual([]);
});

test('a stored v2 channel remains readable and disabled until explicit channel wipe', async ({
  page,
}) => {
  await openVault(page);
  const [a] = await seedPeers(page, true);
  await expect(page.locator('#chat-status-text')).toContainText(
    'Protocol upgrade required',
  );
  await expect(page.locator('#chat-input')).toBeDisabled();
  await expect(page.locator('#chat-form button[type=submit]')).toBeDisabled();
  await expect(page.locator('#btn-start-session')).toBeDisabled();
  await expect(page.locator('#btn-attach')).toBeDisabled();
  await expect(page.locator('#media-input')).toBeDisabled();
  await expect(page.locator('#chat-messages')).toContainText(
    'Synthetic retained v2 history',
  );
  const readLegacy = () =>
    page.evaluate(async (fp) => {
      const { DB } = await import('/storage.js');
      return {
        session: await DB.get('sessions', fp),
        messages: await DB.getAll('messages'),
        contact: await DB.get('contacts', fp),
      };
    }, a.fingerprint);
  const before = await readLegacy();
  expect(before.session.version).toBe(2);
  expect(before.messages).toHaveLength(1);
  await page.locator('#btn-peer-menu').click();
  await page.locator('#btn-reset-session').click();
  await page.locator('#btn-cancel-wipe').click();
  expect(await readLegacy()).toEqual(before);
  await expect(page.locator('#chat-messages')).toContainText(
    'Synthetic retained v2 history',
  );
  await page.locator('#btn-peer-menu').click();
  await page.locator('#btn-reset-session').click();
  await page.locator('#btn-confirm-wipe').click();
  await expect(page.locator('#chat-status-text')).toHaveText('Idle');
  await expect(page.locator('#chat-messages')).not.toContainText(
    'Synthetic retained v2 history',
  );
  await expect(page.locator('#btn-start-session')).toBeEnabled();
  const after = await readLegacy();
  expect(after.session).toBeUndefined();
  expect(after.messages).toEqual([]);
  expect(after.contact).toEqual(before.contact);
});

test('a confirmed peer deletion queued on the state lock expires when its modal is canceled', async ({
  page,
}) => {
  await openVault(page);
  const [a] = await seedPeers(page, true);
  await expect(page.locator('#chat-messages')).toContainText(
    'Synthetic retained v2 history',
  );
  const before = await readPeerState(page, a.fingerprint);
  await page.locator('#btn-peer-menu').click();
  await page.locator('#btn-delete-contact').click();
  await queueConfirmedAction(page, '#btn-confirm-del');
  try {
    await page.locator('#btn-cancel-del').click();
    await expect(page.locator('#modal-overlay')).toBeHidden();
    await page.locator('#btn-global-settings').click();
    await expect(page.locator('#modal-container')).toContainText(
      'Encrypted local vault',
    );
  } finally {
    await releaseConfirmedAction(page);
  }
  expect(await readPeerState(page, a.fingerprint)).toEqual(before);
  await expect(page.locator('#chat-title')).toHaveText('Synthetic Peer A');
  await expect(page.locator('#chat-messages')).toContainText(
    'Synthetic retained v2 history',
  );
  await expect(page.locator('#modal-overlay')).toBeVisible();
  await expect(page.locator('#modal-container')).toContainText(
    'Encrypted local vault',
  );
  await expect(page.locator('#toast-msg')).not.toContainText('Peer deleted.');
});

test('a confirmed channel wipe queued on the state lock expires after peer navigation', async ({
  page,
}) => {
  await openVault(page);
  const [a, b] = await seedPeers(page, true);
  await expect(page.locator('#chat-messages')).toContainText(
    'Synthetic retained v2 history',
  );
  const before = await readPeerState(page, a.fingerprint);
  await page.locator('#btn-peer-menu').click();
  await page.locator('#btn-reset-session').click();
  await queueConfirmedAction(page, '#btn-confirm-wipe');
  try {
    // Navigation invalidates A's modal before B's last-read update can acquire
    // the held state lock. Wait for that invalidation before releasing it.
    await page.evaluate((fp) => {
      location.hash = `#${fp}`;
    }, b.fingerprint);
    await expect(page.locator('#modal-overlay')).toBeHidden();
  } finally {
    await releaseConfirmedAction(page);
  }
  expect(await readPeerState(page, a.fingerprint)).toEqual(before);
  await expect(page.locator('#chat-title')).toHaveText('Synthetic Peer B');
  await expect(page.locator('#chat-status-text')).toHaveText('Idle');
  await expect(page.locator('#chat-messages')).not.toContainText(
    'Synthetic retained v2 history',
  );
  await expect(page.locator('#modal-overlay')).toBeHidden();
  await expect(page.locator('#toast-msg')).not.toContainText(
    'Channel state wiped.',
  );
});

test('identity reads queued before lock expire while the original keys survive unlock', async ({
  page,
}) => {
  await openVault(page);
  const result = await page.evaluate(async (passphrase) => {
    const { DB, Vault } = await import('/storage.js');
    const { getLocalIdentity } = await import('/identity.js');
    const { withNamedLock } = await import('/locks.js');
    const original = (await getLocalIdentity()).ecPk;
    let release;
    let entered;
    const started = new Promise((resolve) => {
      entered = resolve;
    });
    const held = withNamedLock('identity', async () => {
      entered();
      await new Promise((resolve) => {
        release = resolve;
      });
    });
    await started;
    const pending = getLocalIdentity().then(
      () => 'unexpected success',
      () => 'expired',
    );
    Vault.lock();
    await Vault.unlock(passphrase);
    release();
    await held;
    const outcome = await pending;
    const current = (await getLocalIdentity()).ecPk;
    return {
      outcome,
      unchanged: original.every((byte, index) => byte === current[index]),
      identityCount: (await DB.getAll('identity')).length,
    };
  }, passphrase);
  expect(result).toEqual({
    outcome: 'expired',
    unchanged: true,
    identityCount: 1,
  });
});

test('deferred modal autofocus cannot redirect fingerprint entry to the alias input', async ({
  page,
}) => {
  await openVault(page);
  const peer = await syntheticIdentity(page);
  await page.evaluate((value) => {
    window.testClipboard = value;
    window.savedRequestAnimationFrame = window.requestAnimationFrame;
    window.deferredFrames = [];
    window.requestAnimationFrame = (callback) => {
      window.deferredFrames.push(callback);
      return window.deferredFrames.length;
    };
  }, peer.envelope);
  await page.locator('#btn-add-contact').click();
  await page.locator('#new-alias-input').fill('Synthetic delayed-focus peer');
  await page.evaluate(() => {
    // Firefox/Playwright focus and text insertion are separate operations.
    // Release the application's delayed frame precisely as entry moves to
    // the fingerprint input, rather than depending on background-tab timing.
    document.querySelector('#verified-fp-input').addEventListener(
      'focus',
      () => {
        queueMicrotask(() => {
          window.requestAnimationFrame = window.savedRequestAnimationFrame;
          for (const callback of window.deferredFrames.splice(0))
            callback(performance.now());
        });
      },
      { once: true },
    );
  });
  await page.locator('#verified-fp-input').fill(peer.fingerprint);
  await expect(page.locator('#verified-fp-input')).toBeFocused();
  await expect(page.locator('#verified-fp-input')).toHaveValue(
    peer.fingerprint,
  );
  await expect(page.locator('#new-alias-input')).toHaveValue(
    'Synthetic delayed-focus peer',
  );
  await page.locator('#btn-confirm-add').click();
  await expect(page.locator('#contacts-list')).toContainText(
    'Synthetic delayed-focus peer',
  );
});

test('vault recreation controls stay disabled until pending deletion completes', async ({
  page,
}) => {
  await openVault(page);
  // Exclude the preceding create submission from the destruction interleaving.
  await expect(page.locator('#vault-submit')).toBeEnabled();
  await page.evaluate(async () => {
    window.pendingDeletionLock = navigator.locks.request(
      'ECP_SECURE_DB_v2:state',
      () =>
        new Promise((resolve) => {
          window.deletionLockHeld = true;
          window.releaseDeletionLock = resolve;
        }),
    );
  });
  await expect
    .poll(() => page.evaluate(() => window.deletionLockHeld))
    .toBe(true);
  page.on('dialog', (dialog) => dialog.accept());
  await page.locator('#btn-global-settings').click();
  await page.locator('#btn-destroy-vault').click();
  try {
    await expect(page.locator('#vault-screen')).toBeVisible();
    await expect(page.locator('#vault-submit')).toBeDisabled();
    await expect(page.locator('#vault-password')).toBeDisabled();
    await expect(page.locator('#vault-confirm')).toBeDisabled();
  } finally {
    await page.evaluate(async () => {
      window.releaseDeletionLock();
      await window.pendingDeletionLock;
    });
  }
  await expect(page.locator('#vault-submit')).toHaveText('Create vault');
  await expect(page.locator('#vault-submit')).toBeEnabled();
  await expect(page.locator('#vault-password')).toBeEnabled();
  await expect(page.locator('#vault-confirm')).toBeEnabled();
  await page.locator('#vault-password').fill(passphrase);
  await page.locator('#vault-confirm').fill(passphrase);
  await page.locator('#vault-submit').click();
  await expect(page.locator('#app-root')).toBeVisible();
  await expect(page.locator('#vault-error')).toBeEmpty();
});

test('missing persisted identity rejects normal UI unlock without creating replacement keys', async ({
  page,
}) => {
  await openVault(page);
  await page.evaluate(async () => {
    const { Vault } = await import('/storage.js');
    Vault.lock();
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('ECP_SECURE_DB_v2', 1);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    await new Promise((resolve, reject) => {
      const tx = db.transaction('identity', 'readwrite');
      tx.objectStore('identity').delete('local');
      tx.oncomplete = resolve;
      tx.onabort = () => reject(tx.error);
    });
    db.close();
  });
  await expect(page.locator('#vault-submit')).toHaveText('Unlock');
  await page.locator('#vault-password').fill(passphrase);
  await page.locator('#vault-submit').click();
  await expect(page.locator('#vault-error')).toContainText(
    'identity is missing',
  );
  await expect(page.locator('#app-root')).toBeHidden();
  const result = await page.evaluate(async () => {
    const { Vault } = await import('/storage.js');
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('ECP_SECURE_DB_v2', 1);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const count = await new Promise((resolve, reject) => {
      const tx = db.transaction('identity', 'readonly');
      const req = tx.objectStore('identity').count();
      tx.oncomplete = () => resolve(req.result);
      tx.onabort = () => reject(tx.error);
    });
    db.close();
    return { count, unlocked: Vault.isUnlocked() };
  });
  expect(result).toEqual({ count: 0, unlocked: false });
});
