import { test, expect } from '@playwright/test';

const passphrase = 'synthetic-inactivity-vault-passphrase';
const secret = 'Synthetic inactivity history content';
const messageId = 'synthetic-inactivity-message';
const limit = 5 * 60_000;

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
    // These are synthetic elapsed-time checks, not an OS sleep experiment.
    // Keep native timers running normally: the five-minute timer has not fired
    // when an operation observes a deliberately advanced clock.
    const wallNow = Date.now.bind(Date);
    const monotonicNow = performance.now.bind(performance);
    let wallOffset = 0;
    let monotonicOffset = 0;
    Date.now = () => wallNow() + wallOffset;
    Object.defineProperty(performance, 'now', {
      configurable: true,
      value: () => monotonicNow() + monotonicOffset,
    });
    window.shiftInactivityClock = (wall, monotonic) => {
      wallOffset += wall;
      monotonicOffset += monotonic;
    };
    // Observe before the application's capture listener can consume expired
    // input with stopImmediatePropagation. Only arm this for the tested click.
    window.observeInactivityPointer = false;
    window.overduePointerWasTrusted = false;
    addEventListener(
      'pointerdown',
      (event) => {
        if (!window.observeInactivityPointer) return;
        window.overduePointerWasTrusted = event.isTrusted;
        window.observeInactivityPointer = false;
      },
      { capture: true },
    );
    // Synthetic test packets never reach the operating system clipboard.
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

async function shiftClock(page, wall = limit + 1, monotonic = wall) {
  await page.evaluate(
    ({ wall, monotonic }) => window.shiftInactivityClock(wall, monotonic),
    { wall, monotonic },
  );
}

async function seedVisibleHistory(page) {
  const fingerprint = await page.evaluate(
    async ({ secret, messageId }) => {
      const { DB } = await import('/storage.js');
      const identity = await import('/identity.js');
      const c = await import('/crypto.js');
      const publicIdentity = identity.serializeIdentityPublic({
        ecPk: c.keygenEd25519().publicKey,
        dsaPk: c.keygenMLDSA87().publicKey,
        dhPk: c.keygenX25519().publicKey,
        kemPk: c.keygenMLKEM1024().publicKey,
      });
      const fingerprint = identity.calculateFingerprint(publicIdentity);
      const bundle = c.encodeBase64URL(publicIdentity);
      const conversationId = 'synthetic-inactivity-conversation';
      // This display-only fixture is never used to encrypt protocol packets.
      await DB.putMany([
        [
          'contacts',
          {
            fingerprint,
            bundle,
            name: 'Synthetic Inactivity Peer',
            verified: true,
            archived: false,
            lastReadTimestamp: 0,
          },
        ],
        [
          'sessions',
          {
            contactFp: fingerprint,
            version: 3,
            conversationId,
            peerIdentity: bundle,
            DHs: {
              sk: new Uint8Array(32).fill(1),
              pk: new Uint8Array(32).fill(2),
            },
            RK: new Uint8Array(32).fill(3),
            Ns: 0,
            Nr: 0,
            PN: 0,
            state: 'ESTABLISHED',
          },
        ],
        [
          'messages',
          {
            id: messageId,
            contactFp: fingerprint,
            conversationId,
            text: secret,
            timestamp: 1234,
            isMe: false,
          },
        ],
      ]);
      return fingerprint;
    },
    { secret, messageId },
  );
  await page.evaluate((fp) => {
    location.hash = `#${fp}`;
  }, fingerprint);
  await expect(page.locator('#chat-messages')).toContainText(secret);
  return fingerprint;
}

async function expectLockedAndCleared(page) {
  await expect(page.locator('#app-root')).toBeHidden();
  await expect(page.locator('#vault-screen')).toBeVisible();
  await expect(page.locator('#chat-messages')).toBeEmpty();
  await expect(page.locator('#chat-input')).toHaveValue('');
  await expect(page.locator('#contacts-list')).toBeEmpty();
  expect(
    await page.evaluate(async () =>
      (await import('/storage.js')).Vault.isUnlocked(),
    ),
  ).toBe(false);
}

test('the first trusted pointer input after a delayed deadline locks instead of renewing', async ({
  page,
}) => {
  await openVault(page);
  await seedVisibleHistory(page);
  await page.locator('#chat-input').fill('Synthetic unsent draft');
  const target = await page.locator('#btn-global-settings').boundingBox();
  expect(target).not.toBeNull();
  await page.evaluate(() => {
    window.overduePointerWasTrusted = false;
    window.observeInactivityPointer = true;
  });
  await shiftClock(page);
  await page.mouse.click(
    target.x + target.width / 2,
    target.y + target.height / 2,
  );
  expect(await page.evaluate(() => window.overduePointerWasTrusted)).toBe(true);
  await expectLockedAndCleared(page);
  await expect(page.locator('#modal-overlay')).toBeHidden();
  // A new unlock establishes a new deadline against the current clocks.
  await unlock(page);
  expect(
    await page.evaluate(
      async (id) => (await import('/storage.js')).DB.get('messages', id),
      messageId,
    ),
  ).toMatchObject({ text: secret });
});

for (const eventName of ['focus', 'pageshow', 'visibilitychange']) {
  test(`a ${eventName} resume check observes a delayed inactivity deadline`, async ({
    page,
  }) => {
    await openVault(page);
    await seedVisibleHistory(page);
    await shiftClock(page);
    // Dispatch the lifecycle event only; synthetic input cannot renew activity.
    await page.evaluate((name) => {
      if (name === 'visibilitychange')
        document.dispatchEvent(new Event(name, { bubbles: true }));
      else if (name === 'pageshow')
        dispatchEvent(new PageTransitionEvent(name, { persisted: true }));
      else dispatchEvent(new FocusEvent(name));
    }, eventName);
    await expectLockedAndCleared(page);
  });
}

for (const [clock, wall, monotonic] of [
  ['wall clock elapsed', limit + 1, 0],
  ['monotonic clock elapsed', 0, limit + 1],
  ['wall clock moved backwards', -2 * limit, 0],
  ['monotonic clock moved backwards', 0, -2 * limit],
]) {
  test(`direct storage access expires when ${clock}, without UI activity`, async ({
    page,
  }) => {
    await openVault(page);
    await seedVisibleHistory(page);
    await shiftClock(page, wall, monotonic);
    const result = await page.evaluate(async (id) => {
      try {
        await (await import('/storage.js')).DB.get('messages', id);
        return 'unexpected plaintext read';
      } catch {
        return 'read rejected';
      }
    }, messageId);
    expect(result).toBe('read rejected');
    await expectLockedAndCleared(page);
  });
}

test('an asynchronous decrypt completing after expiry cannot publish its plaintext', async ({
  page,
}) => {
  await openVault(page);
  await seedVisibleHistory(page);
  await page.evaluate(async (id) => {
    const { DB } = await import('/storage.js');
    const message = await DB.get('messages', id);
    if (!message) throw new Error('Synthetic message fixture is missing');
    const delayedId = `${id}-delayed-only`;
    // Route rendering may still be decrypting identity/contact/session records.
    // Give this read its own record outside every displayed conversation so no
    // unrelated UI read can consume its barrier.
    await DB.put('messages', {
      ...message,
      id: delayedId,
      conversationId: 'synthetic-isolated-delayed-conversation',
    });
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    let held = false;
    window.inactivityReadPublished = false;
    window.inactivityReadSettled = false;
    window.inactivityTargetDecrypts = 0;
    crypto.subtle.decrypt = async (...args) => {
      const plaintext = await decrypt(...args);
      const aad = JSON.parse(new TextDecoder().decode(args[0].additionalData));
      const target = aad[3] === 'messages' && aad[4] === delayedId;
      if (target) window.inactivityTargetDecrypts++;
      if (target && !held) {
        held = true;
        window.inactivityDecryptHeld = true;
        await new Promise((resolve) => {
          window.releaseInactivityDecrypt = resolve;
        });
      }
      return plaintext;
    };
    window.inactivityPendingRead = DB.get('messages', delayedId)
      .then(
        () => {
          window.inactivityReadPublished = true;
          return 'unexpected plaintext read';
        },
        () => 'read rejected',
      )
      .finally(() => {
        window.inactivityReadSettled = true;
        crypto.subtle.decrypt = decrypt;
      });
  }, messageId);
  await expect
    .poll(() => page.evaluate(() => window.inactivityDecryptHeld))
    .toBe(true);
  // Verify the intended operation is still waiting before time advances.
  expect(
    await page.evaluate(() => ({
      decrypts: window.inactivityTargetDecrypts,
      published: window.inactivityReadPublished,
      settled: window.inactivityReadSettled,
    })),
  ).toEqual({ decrypts: 1, published: false, settled: false });
  await shiftClock(page);
  const result = await page.evaluate(async () => {
    window.releaseInactivityDecrypt();
    return window.inactivityPendingRead;
  });
  expect(result).toBe('read rejected');
  expect(await page.evaluate(() => window.inactivityReadPublished)).toBe(false);
  await expectLockedAndCleared(page);
});

test('an expired tab broadcasts its lock even while another tab remains active', async ({
  page,
  context,
}) => {
  await openVault(page);
  await seedVisibleHistory(page);
  const active = await context.newPage();
  await openVault(active, false);
  await active.keyboard.press('Shift');
  expect(
    await active.evaluate(async () =>
      (await import('/storage.js')).Vault.isUnlocked(),
    ),
  ).toBe(true);
  await shiftClock(page);
  expect(
    await active.evaluate(async () =>
      (await import('/storage.js')).Vault.isUnlocked(),
    ),
  ).toBe(true);
  await page.evaluate(() => dispatchEvent(new FocusEvent('focus')));
  await expectLockedAndCleared(page);
  await expectLockedAndCleared(active);
  await unlock(active);
});

test('trusted keyboard activity renews a live deadline without reviving an expired one', async ({
  page,
}) => {
  await openVault(page);
  await seedVisibleHistory(page);
  await shiftClock(page, 4 * 60_000);
  await page.keyboard.press('Shift');
  await shiftClock(page, 2 * 60_000);
  expect(
    await page.evaluate(
      async (id) => (await import('/storage.js')).DB.get('messages', id),
      messageId,
    ),
  ).toMatchObject({ text: secret });
  await shiftClock(page, 3 * 60_000 + 1);
  await page.keyboard.press('Shift');
  await expectLockedAndCleared(page);
});
