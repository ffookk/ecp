import { spawnSync } from 'node:child_process';
import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, relative, join } from 'node:path';

const root = resolve(import.meta.dirname, '..');
process.chdir(root);
// The only inline executable configuration is the import map. Keep its CSP
// hash tied to the exact bytes after formatting or editing the HTML.
const html = await readFile('index.html', 'utf8');
const importMap = html.match(/<script type="importmap">([\s\S]*?)<\/script>/);
if (!importMap) throw new Error('Missing import map');
const importHash = createHash('sha256').update(importMap[1]).digest('base64');
const securedHtml = html.replace(
  /script-src 'self' 'sha256-[^']+'/,
  `script-src 'self' 'sha256-${importHash}'`,
);
if (!securedHtml.includes(`script-src 'self' 'sha256-${importHash}'`))
  throw new Error('Missing script CSP');
if (securedHtml !== html) await writeFile('index.html', securedHtml);
function run(file, args) {
  const result = spawnSync(process.execPath, [file, ...args], {
    stdio: 'inherit',
  });
  if (result.status !== 0) throw new Error(`Build command failed: ${file}`);
}
run('node_modules/typescript/bin/tsc', []);
run('node_modules/@tailwindcss/cli/dist/index.mjs', [
  '-i',
  'src/main.css',
  '-o',
  'main.css',
  '--minify',
]);
// Keep the source tree's browser-resolvable dependency copies identical to npm ci.
for (const name of ['ciphers', 'curves', 'hashes', 'post-quantum']) {
  await rm(`vendor/@noble/${name}`, { recursive: true, force: true });
  await cp(`node_modules/@noble/${name}`, `vendor/@noble/${name}`, {
    recursive: true,
  });
}
await rm('dist', { recursive: true, force: true });
await mkdir('dist');
const assets = [
  'index.html',
  '404.html',
  'main.css',
  'favicon.ico',
  'icon-192.png',
  'icon-512.png',
  'manifest.json',
  'sw.js',
];
for (const name of await readdir('src'))
  if (name.endsWith('.ts')) assets.push(name.replace(/\.ts$/, '.js'));
for (const file of assets) await cp(file, `dist/${file}`);
for (const name of ['ciphers', 'curves', 'hashes', 'post-quantum']) {
  await cp(`vendor/@noble/${name}`, `dist/vendor/@noble/${name}`, {
    recursive: true,
    filter: (source) => !source.endsWith('.ts') && !source.endsWith('.map'),
  });
}
async function files(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const output = [];
  for (const e of entries) {
    const path = join(dir, e.name);
    if (e.isDirectory()) output.push(...(await files(path)));
    else output.push(path);
  }
  return output.sort();
}
const sums = {};
for (const path of await files('dist'))
  sums[relative('dist', path).replaceAll('\\', '/')] = createHash('sha256')
    .update(await readFile(path))
    .digest('hex');
await writeFile('dist/SHA256SUMS.json', JSON.stringify(sums, null, 2) + '\n');
console.log(
  `Built ${Object.keys(sums).length} static assets in dist/. No deployment performed.`,
);
