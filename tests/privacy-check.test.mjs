import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  rm,
  symlink,
  readdir,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { scanRepository } from '../scripts/privacy-check.mjs';
import { packageClient } from '../scripts/package.mjs';

const gitExecutable = process.env.ECP_GIT_PATH || 'git';
const project = resolve(import.meta.dirname, '..');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
async function repo(t) {
  const root = await mkdtemp(join(tmpdir(), 'ecp-privacy-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const env = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_AUTHOR_NAME: 'Synthetic Publisher',
    GIT_COMMITTER_NAME: 'Synthetic Publisher',
    GIT_AUTHOR_EMAIL: '12345+synthetic@users.noreply.github.com',
    GIT_COMMITTER_EMAIL: '12345+synthetic@users.noreply.github.com',
  };
  const git = (args, override = {}) => {
    const result = spawnSync(gitExecutable, ['-C', root, ...args], {
      env: { ...env, ...override },
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, 'synthetic Git fixture setup must succeed');
    return result.stdout.trim();
  };
  git(['-c', 'init.templateDir=', 'init', '-q', '-b', 'main']);
  const put = async (name, text, stage = true) => {
    await mkdir(join(root, name, '..'), { recursive: true });
    await writeFile(join(root, name), text);
    if (stage) git(['add', '--', name]);
  };
  const commit = (message = 'Synthetic fixture', override) =>
    git(
      ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', message],
      override,
    );
  return {
    root,
    git,
    put,
    commit,
    scan: (options) => scanRepository(root, { gitExecutable, ...options }),
  };
}

test('publication checker accepts an unborn clean index and clean noreply history', async (t) => {
  const r = await repo(t);
  await r.put('README.md', 'Synthetic public project.\n');
  assert.deepEqual(r.scan().findings, []);
  r.commit();
  const result = r.scan();
  assert.deepEqual(result.findings, []);
  assert.equal(result.counts.commits, 1);
  assert.equal(result.counts.indexEntries, 1);
});

test('publication checker scans staged content even after the worktree is cleaned, without printing values', async (t) => {
  const r = await repo(t);
  const syntheticToken = ['ghp_', 'A'.repeat(36)].join('');
  await r.put('configuration.txt', syntheticToken);
  await r.put('configuration.txt', 'clean working copy', false);
  const result = r.scan();
  assert.ok(
    result.findings.some(
      (f) => f.category === 'GITHUB_TOKEN' && f.location.startsWith('index:'),
    ),
  );
  assert.ok(!JSON.stringify(result).includes(syntheticToken));
  const cli = spawnSync(
    process.execPath,
    [join(project, 'scripts/privacy-check.mjs'), '--repo', r.root],
    { env: { ...process.env, ECP_GIT_PATH: gitExecutable }, encoding: 'utf8' },
  );
  assert.equal(cli.status, 1);
  assert.ok(!cli.stdout.includes(syntheticToken));
  assert.ok(!cli.stderr.includes(syntheticToken));
  assert.ok(!cli.stdout.includes(r.root));
});

test('publication checker scans every reachable branch and tag metadata, including deleted files', async (t) => {
  const r = await repo(t);
  await r.put('README.md', 'Public data');
  r.commit();
  r.git(['checkout', '-q', '-b', 'old-work']);
  const syntheticPath = [
    '/',
    'Users',
    '/',
    'synthetic-person',
    '/private-note',
  ].join('');
  await r.put('old.txt', syntheticPath);
  r.commit();
  r.git(['rm', '-q', 'old.txt']);
  r.commit('Remove synthetic file');
  r.git(['checkout', '-q', 'main']);
  const syntheticToken = ['AIza', 'B'.repeat(35)].join('');
  r.git([
    '-c',
    'tag.gpgSign=false',
    'tag',
    '-a',
    'fixture-tag',
    '-m',
    syntheticToken,
  ]);
  const result = r.scan();
  assert.ok(
    result.findings.some(
      (f) =>
        f.category === 'LOCAL_USER_PATH' &&
        f.location.startsWith('history:blob:'),
    ),
  );
  assert.ok(
    result.findings.some(
      (f) =>
        f.category === 'GOOGLE_API_KEY' &&
        f.location.startsWith('history:tag:'),
    ),
  );
  assert.ok(!JSON.stringify(result).includes(syntheticPath));
  assert.ok(!JSON.stringify(result).includes(syntheticToken));
});

test('new author and committer emails must be noreply; only exact inherited ancestry is exempt', async (t) => {
  const r = await repo(t);
  const publicUpstreamAddress = [
    'synthetic-upstream',
    '@',
    'example.invalid',
  ].join('');
  const override = {
    GIT_AUTHOR_EMAIL: publicUpstreamAddress,
    GIT_COMMITTER_EMAIL: publicUpstreamAddress,
  };
  await r.put('README.md', 'Inherited public project');
  r.commit('Inherited fixture', override);
  const upstreamBase = r.git(['rev-parse', 'HEAD']);
  assert.equal(
    r.scan().findings.filter((f) => f.category === 'NON_NOREPLY_COMMIT_EMAIL')
      .length,
    2,
  );
  assert.deepEqual(r.scan({ upstreamBase }).findings, []);
  await r.put('README.md', 'New fork work');
  r.commit('New fixture', override);
  const result = r.scan({ upstreamBase });
  assert.equal(
    result.findings.filter((f) => f.category === 'NON_NOREPLY_COMMIT_EMAIL')
      .length,
    2,
  );
  assert.ok(!JSON.stringify(result).includes(publicUpstreamAddress));
});

test('only the exact GitHub service noreply address is exempt for synthetic merge commits', async (t) => {
  for (const [address, accepted] of [
    ['noreply@github.com', true],
    ['synthetic-person@example.invalid', false],
    ['synthetic-person@github.com', false],
    ['noreply@github.com.example.invalid', false],
  ]) {
    const r = await repo(t);
    await r.put('README.md', 'Synthetic merge metadata fixture');
    r.commit('Synthetic merge commit', {
      GIT_AUTHOR_EMAIL: address,
      GIT_COMMITTER_EMAIL: address,
    });
    const findings = r
      .scan()
      .findings.filter((f) => f.category === 'NON_NOREPLY_COMMIT_EMAIL');
    assert.equal(findings.length, accepted ? 0 : 2);
    assert.ok(!JSON.stringify(findings).includes(address));
  }
});

test('private-key markers and embedded binary credentials are detected without revealing them', async (t) => {
  const r = await repo(t);
  const marker = ['-----BEGIN ', 'PRIVATE KEY', '-----'].join('');
  await r.put('key.txt', marker + '\nsynthetic-placeholder\n');
  const token = ['AKIA', 'C'.repeat(16)].join('');
  await r.put(
    'binary.dat',
    Buffer.concat([
      Buffer.from([0, 255, 0]),
      Buffer.from(token),
      Buffer.from([0]),
    ]),
  );
  const result = r.scan();
  assert.ok(result.findings.some((f) => f.category === 'PRIVATE_KEY'));
  assert.ok(result.findings.some((f) => f.category === 'AWS_ACCESS_KEY'));
  assert.ok(!JSON.stringify(result).includes(marker));
  assert.ok(!JSON.stringify(result).includes(token));
});

test('prohibited credential, profile, dependency and report names are rejected in index and historical trees', async (t) => {
  const r = await repo(t);
  for (const name of [
    '.env',
    'node_modules/library/index.js',
    'browser-profile/Default/Cookies',
    'work/audit.txt',
    'outputs/report.md',
  ])
    await r.put(name, 'synthetic harmless contents');
  assert.ok(
    r
      .scan()
      .findings.some(
        (f) =>
          f.category === 'FORBIDDEN_PATH' && f.location.startsWith('index:'),
      ),
  );
  r.commit();
  r.git(['rm', '-q', '-r', '.']);
  await r.put('README.md', 'Clean current index');
  r.commit('Remove private-like fixtures');
  const result = r.scan();
  assert.ok(
    result.findings.some(
      (f) =>
        f.category === 'FORBIDDEN_PATH' &&
        f.location.startsWith('history:tree:'),
    ),
  );
});

test('commit messages are scanned and oversized staged objects fail closed', async (t) => {
  const r = await repo(t);
  await r.put('README.md', 'Public data');
  const syntheticPath = ['/', 'home', '/', 'synthetic-person', '/work'].join(
    '',
  );
  r.commit(`Synthetic metadata ${syntheticPath}`);
  assert.ok(
    r
      .scan()
      .findings.some(
        (f) =>
          f.category === 'LOCAL_USER_PATH' && f.location.includes(':commit:'),
      ),
  );
  await r.put('large.dat', Buffer.alloc(16 * 1024 * 1024 + 1, 0));
  assert.ok(
    r.scan().findings.some((f) => f.category === 'OBJECT_TOO_LARGE_TO_SCAN'),
  );
});

test('shallow checkouts cannot claim complete history coverage', async (t) => {
  const r = await repo(t);
  await r.put('README.md', 'First');
  r.commit();
  await r.put('README.md', 'Second');
  r.commit();
  // A shallow boundary is sufficient to simulate a checkout missing ancestry.
  await writeFile(
    join(r.root, '.git/shallow'),
    r.git(['rev-parse', 'HEAD']) + '\n',
  );
  assert.ok(r.scan().findings.some((f) => f.category === 'INCOMPLETE_HISTORY'));
});

async function packageFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ecp-package-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'dist'));
  await mkdir(join(root, 'scripts'));
  await mkdir(join(root, 'docs'));
  await writeFile(
    join(root, 'dist/index.html'),
    '<!doctype html><title>Synthetic client</title>',
  );
  await writeFile(join(root, 'LICENSE'), 'Synthetic license fixture');
  await writeFile(
    join(root, 'SECURITY.md'),
    'Synthetic offline security policy',
  );
  await writeFile(
    join(root, 'docs/PROTOCOL.md'),
    'Synthetic offline protocol documentation',
  );
  await writeFile(
    join(root, 'scripts/serve.mjs'),
    await readFile(join(project, 'scripts/serve.mjs')),
  );
  await writeFile(
    join(root, 'dist/SHA256SUMS.json'),
    JSON.stringify({
      'index.html': digest(await readFile(join(root, 'dist/index.html'))),
    }),
  );
  return root;
}

test('offline package contains only verified payloads, a built-in server, and deterministic whole-package hashes', async (t) => {
  const root = await packageFixture(t);
  await packageClient(root);
  const packageRoot = join(root, 'build-package');
  const first = await readFile(join(packageRoot, 'SHA256SUMS.json'), 'utf8');
  const manifest = JSON.parse(first);
  assert.deepEqual(
    Object.keys(manifest).sort(),
    [
      'LICENSE',
      'README.md',
      'SECURITY.md',
      'docs/PROTOCOL.md',
      'dist/SHA256SUMS.json',
      'dist/index.html',
      'scripts/serve.mjs',
    ].sort(),
  );
  for (const [name, expected] of Object.entries(manifest))
    assert.equal(digest(await readFile(join(packageRoot, name))), expected);
  assert.ok(!(await readdir(packageRoot)).includes('node_modules'));
  await packageClient(root);
  assert.equal(
    await readFile(join(packageRoot, 'SHA256SUMS.json'), 'utf8'),
    first,
  );
  const socket = createServer();
  await new Promise((resolve) => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  const child = spawn(process.execPath, ['scripts/serve.mjs'], {
    cwd: packageRoot,
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => child.kill());
  await new Promise((resolve, reject) => {
    child.stdout.once('data', resolve);
    child.once('error', reject);
    child.once('exit', (code) =>
      reject(new Error(`Local server exited with ${code}`)),
    );
  });
  const response = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(response.status, 200);
  assert.ok((await response.text()).includes('Synthetic client'));
  child.kill();
});

test('offline packaging scans included security and protocol documents before replacing output', async (t) => {
  const root = await packageFixture(t);
  await packageClient(root);
  const original = await readFile(
    join(root, 'build-package/SHA256SUMS.json'),
    'utf8',
  );
  const syntheticToken = ['ghp_', 'D'.repeat(36)].join('');
  for (const name of ['SECURITY.md', 'docs/PROTOCOL.md']) {
    const previous = await readFile(join(root, name));
    await writeFile(join(root, name), syntheticToken);
    await assert.rejects(
      packageClient(root),
      /privacy rule matched package support/,
    );
    await writeFile(join(root, name), previous);
    assert.equal(
      await readFile(join(root, 'build-package/SHA256SUMS.json'), 'utf8'),
      original,
    );
  }
});

test('offline packaging rejects extra files, changed payloads, and symlinks before replacing the output', async (t) => {
  const root = await packageFixture(t);
  await packageClient(root);
  const original = await readFile(
    join(root, 'build-package/SHA256SUMS.json'),
    'utf8',
  );
  await writeFile(join(root, 'dist/unreviewed.txt'), 'Unexpected');
  await assert.rejects(packageClient(root), /inventory/);
  await rm(join(root, 'dist/unreviewed.txt'));
  await writeFile(join(root, 'dist/index.html'), 'Changed after build');
  await assert.rejects(packageClient(root), /content/);
  await symlink(join(root, 'LICENSE'), join(root, 'dist/link'));
  await assert.rejects(packageClient(root), /symlink/);
  assert.equal(
    await readFile(join(root, 'build-package/SHA256SUMS.json'), 'utf8'),
    original,
  );
});
