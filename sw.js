// Retire earlier cache-first workers when this file replaces an older build.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil((async () => {
  for (const name of await caches.keys()) if (name.startsWith('ecp-')) await caches.delete(name);
  await self.registration.unregister();
})()));
