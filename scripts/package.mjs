import {
  cp,
  lstat,
  mkdir,
  readdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join, relative, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inspectContent, forbiddenPath } from './privacy-check.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
async function files(directory, base = directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory()))
      throw new Error('Package input contains a symlink or special file.');
    if (entry.isDirectory()) output.push(...(await files(path, base)));
    else output.push(relative(base, path).replaceAll('\\', '/'));
  }
  return output.sort();
}

const instructions = `# ECP Hardened — offline local package

This package contains the built experimental client and a local HTTP server.
It needs Node.js 22 or newer and a compatible browser. It has no runtime npm
dependencies: do not run npm install inside this directory.

From this directory, start the server:

\`\`\`sh
node scripts/serve.mjs
\`\`\`

Open http://127.0.0.1:4173 in a browser supporting Web Crypto, Web Locks,
IndexedDB and clipboard access. The server binds only to the loopback interface.
Keep this server running while using the client. The PORT environment variable
can select another port. Keep using the same origin and browser profile:
changing the host or port selects different browser storage.

Once Node.js is installed and this package has been obtained, client serving
requires no network download. Deliver copied encrypted packets through a
transport you choose. Browser permissions and your transport can still affect
clipboard access and delivery.

This is a custom, independently unaudited protocol. Verify full peer
fingerprints through a separate trusted channel. Use a strong vault passphrase;
there is no backup, passphrase recovery or supported session migration.
Do not clone or restore active session databases: this can repeat ratchet keys,
counters and replay history. Protocol v3 uses fresh message nonces and AES-GCM-SIV
to mitigate nonce misuse; these measures do not establish snapshot freshness.
Use fresh identities and newly verified channels after a profile restore.
An unlocked page can access plaintext. Clipboard history, endpoint compromise,
traffic metadata and secure deletion are outside the vault's protection.

SHA256SUMS.json records the SHA-256 digest of every package payload file,
including the build's nested manifest; the top-level manifest excludes itself.
These hashes detect changes relative to this manifest. They are not signatures
and do not establish the identity or trustworthiness of the package publisher.

No installation, deployment, release or publication is performed by this
package. Review the included SECURITY.md and docs/PROTOCOL.md, and the source,
before relying on this client.
Original project: https://github.com/jamesliu96/ecp (James Liu, MIT license).
See the included LICENSE. This fork does not imply upstream endorsement.
`;

export async function packageClient(
  repository = resolve(import.meta.dirname, '..'),
) {
  const root = resolve(repository);
  const dist = join(root, 'dist');
  const target = join(root, 'build-package');
  const manifest = JSON.parse(
    await readFile(join(dist, 'SHA256SUMS.json'), 'utf8'),
  );
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest))
    throw new Error('Invalid build manifest.');
  const names = await files(dist);
  const expected = [...Object.keys(manifest), 'SHA256SUMS.json'].sort();
  if (
    JSON.stringify(names) !== JSON.stringify(expected) ||
    !names.includes('index.html')
  )
    throw new Error(
      'Build inventory differs from its manifest. Rebuild before packaging.',
    );
  for (const name of names) {
    if (
      !/^(?:[A-Za-z0-9@_.-]+\/)*[A-Za-z0-9@_.-]+$/.test(name) ||
      name.split('/').includes('..') ||
      forbiddenPath(name)
    )
      throw new Error('Disallowed package input name.');
    const bytes = await readFile(join(dist, name));
    if (
      name !== 'SHA256SUMS.json' &&
      (!/^[0-9a-f]{64}$/.test(manifest[name]) || hash(bytes) !== manifest[name])
    )
      throw new Error(
        'Build content differs from its manifest. Rebuild before packaging.',
      );
    if (inspectContent(bytes).length)
      throw new Error('Publication privacy rule matched package input.');
  }
  const support = new Map();
  for (const name of [
    'scripts/serve.mjs',
    'LICENSE',
    'SECURITY.md',
    'docs/PROTOCOL.md',
  ]) {
    const source = join(root, name);
    if (!(await lstat(source)).isFile())
      throw new Error(
        'Package support files must be regular files, not symlinks.',
      );
    const bytes = await readFile(source);
    if (inspectContent(bytes).length)
      throw new Error(
        'Publication privacy rule matched package support files.',
      );
    support.set(name, bytes);
  }
  const server = support.get('scripts/serve.mjs');
  const imports = [
    ...server.toString().matchAll(/\bfrom\s+['"]([^'"]+)['"]/g),
  ].map((match) => match[1]);
  if (!imports.length || imports.some((name) => !name.startsWith('node:')))
    throw new Error('The local server must use only Node.js built-in modules.');

  await rm(target, { recursive: true, force: true });
  await mkdir(join(target, 'scripts'), { recursive: true });
  await cp(dist, join(target, 'dist'), { recursive: true, dereference: false });
  for (const [name, bytes] of support) {
    await mkdir(dirname(join(target, name)), { recursive: true });
    await writeFile(join(target, name), bytes);
  }
  await writeFile(join(target, 'README.md'), instructions);
  const sums = {};
  for (const name of await files(target))
    sums[name] = hash(await readFile(join(target, name)));
  await writeFile(
    join(target, 'SHA256SUMS.json'),
    JSON.stringify(sums, null, 2) + '\n',
  );
  return { files: Object.keys(sums).length, directory: 'build-package' };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const result = await packageClient();
    console.log(
      `Prepared ${result.files} payload files in build-package/. No publication performed.`,
    );
  } catch {
    console.error(
      'PACKAGE_REJECTED: build inventory, integrity, privacy or local-server validation failed.',
    );
    process.exitCode = 1;
  }
}
