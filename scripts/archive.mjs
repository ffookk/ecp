import { constants } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  opendir,
  realpath,
  rename,
  rm,
} from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { forbiddenPath, inspectContent } from './privacy-check.mjs';

export const ARCHIVE_LIMITS = Object.freeze({
  maxFiles: 4096,
  maxEntries: 8192,
  maxFileBytes: 16 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024,
  maxManifestBytes: 1024 * 1024,
  maxPathBytes: 255,
  maxDepth: 16,
});

const MANIFEST = 'SHA256SUMS.json';
const OUTPUT = 'ecp-local-client.tar';
const REJECTED =
  'ARCHIVE_REJECTED: package inventory, integrity, privacy or archive validation failed.';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

function archivePath(name) {
  const parts = name.split('/');
  if (
    name.length > ARCHIVE_LIMITS.maxPathBytes ||
    parts.length > ARCHIVE_LIMITS.maxDepth ||
    parts.some(
      (part) =>
        !/^[A-Za-z0-9@_.-]+$/.test(part) || part === '.' || part === '..',
    ) ||
    forbiddenPath(name) ||
    inspectContent(name).length
  )
    throw new Error(REJECTED);
  if (name.length <= 100) return { name, prefix: '' };
  // POSIX USTAR stores long paths in a 155-byte prefix and 100-byte name.
  for (
    let at = name.lastIndexOf('/');
    at > 0;
    at = name.lastIndexOf('/', at - 1)
  )
    if (at <= 155 && name.length - at - 1 <= 100)
      return { name: name.slice(at + 1), prefix: name.slice(0, at) };
  throw new Error(REJECTED);
}

async function inventory(directory) {
  if (!(await lstat(directory)).isDirectory()) throw new Error(REJECTED);
  const files = [];
  let entries = 0;
  let total = 0;
  async function visit(prefix = '') {
    for await (const entry of await opendir(join(directory, prefix))) {
      if (++entries > ARCHIVE_LIMITS.maxEntries) throw new Error(REJECTED);
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      archivePath(name);
      const stat = await lstat(join(directory, name));
      if (stat.isDirectory()) await visit(name);
      else if (stat.isFile()) {
        if (
          files.length >= ARCHIVE_LIMITS.maxFiles ||
          stat.size > ARCHIVE_LIMITS.maxFileBytes ||
          (name === MANIFEST && stat.size > ARCHIVE_LIMITS.maxManifestBytes)
        )
          throw new Error(REJECTED);
        total += stat.size;
        if (total > ARCHIVE_LIMITS.maxTotalBytes) throw new Error(REJECTED);
        files.push({ name, stat });
      } else throw new Error(REJECTED);
    }
  }
  await visit();
  return files.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function sameFile(left, right) {
  return (
    right.isFile() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function snapshot(directory, { name, stat }) {
  // Bound allocation before reading; a concurrently growing input cannot make
  // readFile allocate beyond the validated size. Never read special files.
  const file = await open(
    join(directory, name),
    constants.O_RDONLY |
      (constants.O_NOFOLLOW || 0) |
      (constants.O_NONBLOCK || 0),
  );
  try {
    if (!sameFile(stat, await file.stat())) throw new Error(REJECTED);
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await file.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!bytesRead) throw new Error(REJECTED);
      offset += bytesRead;
    }
    if (!sameFile(stat, await file.stat()) || inspectContent(bytes).length)
      throw new Error(REJECTED);
    return bytes;
  } finally {
    await file.close();
  }
}

function header(path, size) {
  const { name, prefix } = archivePath(path);
  const bytes = Buffer.alloc(512);
  const text = (value, offset) => bytes.write(value, offset, 'ascii');
  const octal = (value, offset, length) =>
    text(value.toString(8).padStart(length - 1, '0') + '\0', offset);
  text(name, 0);
  octal(0o644, 100, 8);
  octal(0, 108, 8);
  octal(0, 116, 8);
  octal(size, 124, 12);
  octal(0, 136, 12);
  bytes.fill(0x20, 148, 156);
  text('0', 156);
  text('ustar\0', 257);
  text('00', 263);
  // Empty link/owner/group names and zero device fields are deterministic.
  octal(0, 329, 8);
  octal(0, 337, 8);
  text(prefix, 345);
  const checksum = bytes.reduce((sum, byte) => sum + byte, 0);
  text(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
  return bytes;
}

export async function archivePackage(
  repository = resolve(import.meta.dirname, '..'),
) {
  let temporary;
  try {
    const root = resolve(repository);
    const directory = join(root, 'build-package');
    const names = await inventory(directory);
    const manifestFile = names.find(({ name }) => name === MANIFEST);
    if (!manifestFile) throw new Error(REJECTED);
    const manifestBytes = await snapshot(directory, manifestFile);
    const manifest = JSON.parse(manifestBytes.toString('utf8'));
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest))
      throw new Error(REJECTED);
    const expected = Object.keys(manifest).sort();
    for (const name of expected) {
      archivePath(name);
      if (
        name === MANIFEST ||
        typeof manifest[name] !== 'string' ||
        !/^[0-9a-f]{64}$/.test(manifest[name])
      )
        throw new Error(REJECTED);
    }
    // Canonical serialization also rejects duplicate keys, invalid UTF-8,
    // ambiguous numeric values and alternate spellings in the manifest.
    const canonical =
      JSON.stringify(
        Object.fromEntries(expected.map((name) => [name, manifest[name]])),
        null,
        2,
      ) + '\n';
    if (
      !manifestBytes.equals(Buffer.from(canonical)) ||
      !expected.includes('dist/index.html') ||
      !expected.includes('scripts/serve.mjs') ||
      JSON.stringify(names.map(({ name }) => name)) !==
        JSON.stringify([...expected, MANIFEST].sort())
    )
      throw new Error(REJECTED);

    const chunks = [];
    for (const file of names) {
      const bytes =
        file.name === MANIFEST
          ? manifestBytes
          : await snapshot(directory, file);
      if (file.name !== MANIFEST && hash(bytes) !== manifest[file.name])
        throw new Error(REJECTED);
      chunks.push(header(file.name, bytes.length), bytes);
      if (bytes.length % 512)
        chunks.push(Buffer.alloc(512 - (bytes.length % 512)));
    }
    chunks.push(Buffer.alloc(1024));
    const archive = Buffer.concat(chunks);

    // Validation has completed. Replace only our named archive, atomically;
    // unrelated output files and the last successful archive remain intact.
    const output = join(root, 'build-release');
    try {
      await mkdir(output);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    if (!(await lstat(output)).isDirectory()) throw new Error(REJECTED);
    const destination = join(output, OUTPUT);
    try {
      if (!(await lstat(destination)).isFile()) throw new Error(REJECTED);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const candidate = join(output, `.ecp-archive-${randomUUID()}.tmp`);
    const file = await open(candidate, 'wx', 0o600);
    temporary = candidate;
    try {
      await file.writeFile(archive);
    } finally {
      await file.close();
    }
    await rename(temporary, destination);
    temporary = undefined;
    return {
      files: names.length,
      bytes: archive.length,
      sha256: hash(archive),
      path: `build-release/${OUTPUT}`,
    };
  } catch {
    // Filesystem/JSON errors can include private paths or input contents.
    throw new Error(REJECTED);
  } finally {
    if (temporary) await rm(temporary, { force: true }).catch(() => {});
  }
}

const invoked = process.argv[1]
  ? await realpath(process.argv[1]).catch(() => '')
  : '';
if (invoked && import.meta.url === pathToFileURL(invoked).href) {
  try {
    const result = await archivePackage();
    console.log(
      `Prepared ${result.files} files in ${result.path}. SHA-256: ${result.sha256}`,
    );
  } catch {
    console.error(REJECTED);
    process.exitCode = 1;
  }
}
