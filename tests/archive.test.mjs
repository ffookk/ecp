import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  truncate,
  utimes,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { ARCHIVE_LIMITS, archivePackage } from '../scripts/archive.mjs';

const project = resolve(import.meta.dirname, '..');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const rejected =
  'ARCHIVE_REJECTED: package inventory, integrity, privacy or archive validation failed.';
const outputName = 'build-release/ecp-local-client.tar';

async function fixture(t, extra = {}) {
  const root = await mkdtemp(join(tmpdir(), 'ecp-archive-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const files = {
    LICENSE: Buffer.from('Synthetic license'),
    'dist/index.html': Buffer.from(
      '<!doctype html><title>Synthetic archive</title>',
    ),
    'dist/empty.dat': Buffer.alloc(0),
    'dist/binary.dat': Buffer.from([0, 255, 1, 128, 10]),
    'scripts/serve.mjs': Buffer.from(
      '// Synthetic server fixture; never executed.\n',
    ),
    ...extra,
  };
  for (const [name, bytes] of Object.entries(files)) {
    await mkdir(dirname(join(root, 'build-package', name)), {
      recursive: true,
    });
    await writeFile(join(root, 'build-package', name), bytes);
  }
  const manifest = Object.fromEntries(
    Object.keys(files)
      .sort()
      .map((name) => [name, digest(files[name])]),
  );
  const manifestPath = join(root, 'build-package/SHA256SUMS.json');
  const saveManifest = () =>
    writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  await saveManifest();
  return { root, files, manifest, manifestPath, saveManifest };
}

async function rejectsPreservingOutput(t, mutate) {
  const data = await fixture(t);
  await archivePackage(data.root);
  const original = await readFile(join(data.root, outputName));
  await writeFile(join(data.root, 'build-release/unrelated.txt'), 'Keep me');
  await mutate(data);
  await assert.rejects(archivePackage(data.root), { message: rejected });
  assert.deepEqual(await readFile(join(data.root, outputName)), original);
  assert.equal(
    await readFile(join(data.root, 'build-release/unrelated.txt'), 'utf8'),
    'Keep me',
  );
  assert.deepEqual((await readdir(join(data.root, 'build-release'))).sort(), [
    'ecp-local-client.tar',
    'unrelated.txt',
  ]);
}

function tarHeaders(bytes) {
  const output = [];
  for (let offset = 0; offset < bytes.length - 1024;) {
    const header = bytes.subarray(offset, offset + 512);
    const text = (start, length) =>
      header
        .subarray(start, start + length)
        .toString('ascii')
        .replace(/\0.*$/s, '');
    const octal = (start, length) =>
      Number.parseInt(text(start, length).trim(), 8);
    const name = text(0, 100);
    const prefix = text(345, 155);
    const size = octal(124, 12);
    const checksum = octal(148, 8);
    const checked = Buffer.from(header);
    checked.fill(0x20, 148, 156);
    assert.equal(
      checksum,
      checked.reduce((sum, byte) => sum + byte, 0),
    );
    assert.equal(octal(100, 8), 0o644);
    assert.equal(octal(108, 8), 0);
    assert.equal(octal(116, 8), 0);
    assert.equal(octal(136, 12), 0);
    assert.equal(text(156, 1), '0');
    assert.equal(text(157, 100), '');
    assert.equal(text(257, 6), 'ustar');
    assert.equal(text(263, 2), '00');
    assert.equal(text(265, 32), '');
    assert.equal(text(297, 32), '');
    output.push({ name: prefix ? `${prefix}/${name}` : name, size });
    const padded = Math.ceil(size / 512) * 512;
    assert.deepEqual(
      bytes.subarray(offset + 512 + size, offset + 512 + padded),
      Buffer.alloc(padded - size),
    );
    offset += 512 + padded;
  }
  assert.deepEqual(bytes.subarray(-1024), Buffer.alloc(1024));
  return output;
}

test('archive bytes and fixed USTAR metadata are independent of source mode and timestamps', async (t) => {
  const data = await fixture(t);
  const first = await archivePackage(data.root);
  const original = await readFile(join(data.root, outputName));
  assert.equal(first.path, outputName);
  assert.equal(first.files, Object.keys(data.files).length + 1);
  assert.equal(first.bytes, original.length);
  assert.equal(first.sha256, digest(original));
  const headers = tarHeaders(original);
  assert.deepEqual(
    headers.map(({ name }) => name),
    [...Object.keys(data.files), 'SHA256SUMS.json'].sort(),
  );
  for (const name of [...Object.keys(data.files), 'SHA256SUMS.json']) {
    await chmod(join(data.root, 'build-package', name), 0o755);
    await utimes(join(data.root, 'build-package', name), 123456789, 234567891);
  }
  await chmod(join(data.root, 'build-package/dist'), 0o700);
  await writeFile(join(data.root, 'build-release/unrelated.txt'), 'Keep me');
  assert.deepEqual(await archivePackage(data.root), first);
  assert.deepEqual(await readFile(join(data.root, outputName)), original);
  assert.equal(
    await readFile(join(data.root, 'build-release/unrelated.txt'), 'utf8'),
    'Keep me',
  );
});

test('system tar lists and extracts synthetic USTAR paths and exact binary bytes', async (t) => {
  const longName = `dist/${'p'.repeat(90)}/${'n'.repeat(70)}.dat`;
  const data = await fixture(t, {
    [longName]: Buffer.from('Synthetic long path payload'),
  });
  await archivePackage(data.root);
  const archive = join(data.root, outputName);
  const listed = spawnSync('tar', ['-tf', archive], { encoding: 'utf8' });
  assert.equal(listed.status, 0);
  assert.equal(listed.stderr, '');
  const names = [...Object.keys(data.files), 'SHA256SUMS.json'].sort();
  assert.deepEqual(listed.stdout.trim().split('\n'), names);
  const extracted = join(data.root, 'extracted');
  await mkdir(extracted);
  const result = spawnSync('tar', ['-xf', archive, '-C', extracted], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  for (const [name, bytes] of Object.entries(data.files))
    assert.deepEqual(await readFile(join(extracted, name)), bytes);
  assert.deepEqual(
    await readFile(join(extracted, 'SHA256SUMS.json')),
    await readFile(data.manifestPath),
  );
  assert.deepEqual(
    tarHeaders(await readFile(archive)).map(({ name }) => name),
    names,
  );
});

test('invalid package inputs preserve the last archive and unrelated output', async (t) => {
  const cases = {
    'changed payload': async ({ root }) =>
      writeFile(join(root, 'build-package/dist/index.html'), 'Changed'),
    'extra payload': async ({ root }) =>
      writeFile(join(root, 'build-package/dist/extra.txt'), 'Extra'),
    'missing payload': async ({ root }) =>
      rm(join(root, 'build-package/LICENSE')),
    'missing manifest': async ({ manifestPath }) => rm(manifestPath),
    'malformed manifest': async ({ manifestPath }) =>
      writeFile(manifestPath, '{invalid'),
    'array manifest': async ({ manifestPath }) =>
      writeFile(manifestPath, '[]\n'),
    'null manifest': async ({ manifestPath }) =>
      writeFile(manifestPath, 'null\n'),
    'bad digest': async ({ manifest, saveManifest }) => {
      manifest.LICENSE = 'a'.repeat(63);
      await saveManifest();
    },
    'self entry': async ({ manifest, saveManifest }) => {
      manifest['SHA256SUMS.json'] = 'a'.repeat(64);
      await saveManifest();
    },
    'duplicate manifest key': async ({ manifestPath }) => {
      const text = await readFile(manifestPath, 'utf8');
      await writeFile(
        manifestPath,
        text.replace('{\n', '{\n  "LICENSE": "' + 'a'.repeat(64) + '",\n'),
      );
    },
    'file symlink': async ({ root }) => {
      await rm(join(root, 'build-package/LICENSE'));
      await symlink(
        join(root, 'build-package/dist/index.html'),
        join(root, 'build-package/LICENSE'),
      );
    },
    'directory symlink': async ({ root }) => {
      await mkdir(join(root, 'empty'));
      await symlink(join(root, 'empty'), join(root, 'build-package/linked'));
    },
    'special file': async ({ root }) => {
      const result = spawnSync('mkfifo', [join(root, 'build-package/pipe')]);
      assert.equal(result.status, 0);
    },
    'package root symlink': async ({ root }) => {
      await rm(join(root, 'build-package'), { recursive: true });
      await mkdir(join(root, 'empty'));
      await symlink(join(root, 'empty'), join(root, 'build-package'));
    },
    'unsafe filesystem path': async ({ root }) =>
      writeFile(join(root, 'build-package/bad\\name'), 'Invalid'),
    'forbidden filesystem path': async ({ root }) =>
      writeFile(join(root, 'build-package/.env'), 'Synthetic'),
    'privacy matching content with a valid hash': async ({
      root,
      manifest,
      saveManifest,
    }) => {
      const token = ['ghp_', 'D'.repeat(36)].join('');
      await writeFile(join(root, 'build-package/LICENSE'), token);
      manifest.LICENSE = digest(token);
      await saveManifest();
    },
  };
  for (const [name, mutate] of Object.entries(cases))
    await t.test(name, (subtest) => rejectsPreservingOutput(subtest, mutate));
});

test('unsafe or non-USTAR manifest paths fail closed', async (t) => {
  for (const name of [
    '../outside',
    '/absolute',
    'dist/../outside',
    'dist/./index.html',
    'dist//index.html',
    'bad\\path',
    'dist/\u00e9.txt',
    'dist/' + 'x'.repeat(101),
    'dist/' + 'x'.repeat(251),
  ]) {
    await t.test(JSON.stringify(name), (subtest) =>
      rejectsPreservingOutput(subtest, async ({ manifest, saveManifest }) => {
        manifest[name] = 'a'.repeat(64);
        await saveManifest();
      }),
    );
  }
});

test('archive budgets reject oversized inputs before replacing output', async (t) => {
  await t.test('individual file', (subtest) =>
    rejectsPreservingOutput(subtest, async ({ root }) => {
      await truncate(
        join(root, 'build-package/LICENSE'),
        ARCHIVE_LIMITS.maxFileBytes + 1,
      );
    }),
  );
  await t.test('manifest', (subtest) =>
    rejectsPreservingOutput(subtest, async ({ manifestPath }) => {
      await truncate(manifestPath, ARCHIVE_LIMITS.maxManifestBytes + 1);
    }),
  );
  await t.test('aggregate bytes', (subtest) =>
    rejectsPreservingOutput(subtest, async ({ root }) => {
      for (
        let index = 0;
        index <= ARCHIVE_LIMITS.maxTotalBytes / ARCHIVE_LIMITS.maxFileBytes;
        index++
      ) {
        const name = join(root, 'build-package', `large-${index}`);
        await writeFile(name, '');
        await truncate(name, ARCHIVE_LIMITS.maxFileBytes);
      }
    }),
  );
  await t.test('file count', (subtest) =>
    rejectsPreservingOutput(subtest, async ({ root }) => {
      for (let index = 0; index < ARCHIVE_LIMITS.maxFiles; index++)
        await writeFile(join(root, 'build-package', `count-${index}`), '');
    }),
  );
  await t.test('directory depth', (subtest) =>
    rejectsPreservingOutput(subtest, async ({ root }) => {
      await mkdir(
        join(
          root,
          'build-package',
          ...Array(ARCHIVE_LIMITS.maxDepth + 1).fill('d'),
        ),
        { recursive: true },
      );
    }),
  );
});

test('symlinked output locations are rejected without following them', async (t) => {
  for (const kind of ['directory', 'file']) {
    await t.test(kind, async (subtest) => {
      const { root } = await fixture(subtest);
      const outside = join(root, 'outside');
      await mkdir(outside);
      const sentinel = join(outside, 'sentinel');
      await writeFile(sentinel, 'Keep me');
      if (kind === 'directory')
        await symlink(outside, join(root, 'build-release'));
      else {
        await mkdir(join(root, 'build-release'));
        await symlink(sentinel, join(root, outputName));
      }
      await assert.rejects(archivePackage(root), { message: rejected });
      assert.equal(await readFile(sentinel, 'utf8'), 'Keep me');
      assert.deepEqual(await readdir(outside), ['sentinel']);
    });
  }
});

test('CLI failure diagnostics contain no source paths or rejected content', async (t) => {
  const { root } = await fixture(t);
  await mkdir(join(root, 'scripts'));
  for (const name of ['archive.mjs', 'privacy-check.mjs'])
    await copyFile(join(project, 'scripts', name), join(root, 'scripts', name));
  const sensitive = [
    '/',
    'Users',
    '/',
    'synthetic-private-person',
    '/private.txt',
  ].join('');
  await writeFile(join(root, 'build-package/SHA256SUMS.json'), sensitive);
  const result = spawnSync(
    process.execPath,
    [join(root, 'scripts/archive.mjs')],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, rejected + '\n');
  assert.equal(result.stderr.includes(root), false);
  assert.equal(result.stderr.includes(sensitive), false);
});
