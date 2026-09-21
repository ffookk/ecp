import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Only this reviewed upstream ancestry may retain inherited author metadata.
// New commits must use GitHub noreply addresses, including upstream contributors.
const UPSTREAM_BASE = 'ba4c42f14b08e61cee8a8108bcd8cad99406e7f0';
const MAX_OBJECT = 16 * 1024 * 1024;
const MAX_BATCH = 24 * 1024 * 1024;
const RULES = [
  [
    'LOCAL_USER_PATH',
    /\/(?:Users|home)\/[A-Za-z0-9._-]+|\/(?:var|private\/var)\/folders\/[A-Za-z0-9._/-]+|[A-Za-z]:[\\/]+Users[\\/]+[^\s\\/"'<>]+/g,
  ],
  [
    'PRIVATE_KEY',
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
  ],
  [
    'GITHUB_TOKEN',
    /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,
  ],
  ['AWS_ACCESS_KEY', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['AI_API_KEY', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,255}\b/g],
  ['SLACK_TOKEN', /\bxox[baprs]-[A-Za-z0-9-]{20,255}\b/g],
  ['GOOGLE_API_KEY', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['PAYMENT_SECRET_KEY', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b/g],
  [
    'URL_CREDENTIALS',
    /\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s/@:]+:[^\s/@]+@/g,
  ],
];

/** Return only rule names and line numbers; never retain or print matched values. */
export function inspectContent(content) {
  const text = Buffer.isBuffer(content)
    ? content.toString('utf8')
    : String(content);
  const findings = [];
  for (const [category, pattern] of RULES) {
    pattern.lastIndex = 0;
    let match;
    const lines = new Set();
    while ((match = pattern.exec(text))) {
      const line = text.slice(0, match.index).split('\n').length;
      if (!lines.has(line)) findings.push({ category, line });
      lines.add(line);
    }
  }
  return findings;
}

export function forbiddenPath(path) {
  const parts = path.replaceAll('\\', '/').split('/');
  return parts.some(
    (part) =>
      /^(?:node_modules|work|outputs?|reports?|coverage|playwright-report|test-results|build-package|\.git|\.ssh|\.aws|\.config)$/i.test(
        part,
      ) ||
      /^(?:\.env(?:\..*)?|\.netrc|\.npmrc|credentials(?:\.json|\.ini)?|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|.+\.(?:p12|pfx))$/i.test(
        part,
      ) ||
      /^(?:(?:chrome|chromium|firefox|browser)[-_ ]?profiles?|user[-_ ]?data(?:[-_ ]?dir)?|profile[ _-]?\d+|Default|Cookies|Login Data|Local State)$/i.test(
        part,
      ),
  );
}

function gitRunner(repository, executable) {
  return (args, input, optional = false) => {
    const result = spawnSync(
      executable,
      [
        '--no-replace-objects',
        '-C',
        repository,
        '-c',
        'core.fsmonitor=false',
        ...args,
      ],
      {
        input,
        maxBuffer: 64 * 1024 * 1024,
        env: {
          ...process.env,
          GIT_TERMINAL_PROMPT: '0',
          GIT_NO_REPLACE_OBJECTS: '1',
        },
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );
    if (result.error || result.status !== 0) {
      if (optional) return undefined;
      // Git diagnostics can contain a private path or a hostile object name.
      throw new Error(
        'Git inspection failed; no diagnostics containing repository data were printed.',
      );
    }
    return result.stdout;
  };
}

export function scanRepository(
  repository,
  {
    gitExecutable = process.env.ECP_GIT_PATH || 'git',
    upstreamBase = UPSTREAM_BASE,
  } = {},
) {
  const git = gitRunner(resolve(repository), gitExecutable);
  git(['rev-parse', '--git-dir']);
  const findings = [];
  const add = (category, location) => findings.push({ category, location });
  if (
    git(['rev-parse', '--is-shallow-repository']).toString().trim() !== 'false'
  )
    add('INCOMPLETE_HISTORY', 'repository');

  const index = new Map();
  const indexed = git(['ls-files', '--stage', '-z'])
    .toString('utf8')
    .split('\0')
    .filter(Boolean);
  for (let entry = 0; entry < indexed.length; entry++) {
    const match = indexed[entry].match(
      /^(\d+) ([0-9a-f]+) ([0-3])\t([\s\S]+)$/,
    );
    if (!match) throw new Error('Invalid Git index listing.');
    const [, mode, oid, stage, path] = match;
    if (stage !== '0')
      add('UNMERGED_INDEX', `index:entry-${entry}:object-${oid}`);
    if (mode === '160000')
      add('UNSCANNED_SUBMODULE', `index:entry-${entry}:object-${oid}`);
    if (forbiddenPath(path))
      add('FORBIDDEN_PATH', `index:entry-${entry}:object-${oid}`);
    for (const { category } of inspectContent(path))
      add(category, `index:entry-${entry}:object-${oid}`);
    if (mode !== '160000') index.set(oid, true);
  }

  const reachable = new Set(
    git(['rev-list', '--objects', '--all', '--no-object-names'])
      .toString()
      .trim()
      .split(/\s+/)
      .filter(Boolean),
  );
  const inherited = new Set();
  if (
    /^[0-9a-f]{40,64}$/.test(upstreamBase) &&
    git(['cat-file', '-e', `${upstreamBase}^{commit}`], undefined, true)
  ) {
    for (const oid of git(['rev-list', upstreamBase])
      .toString()
      .trim()
      .split(/\s+/))
      inherited.add(oid);
  }
  const all = [...new Set([...reachable, ...index.keys()])];
  const objectFormat = git(['rev-parse', '--show-object-format'])
    .toString()
    .trim();
  if (!['sha1', 'sha256'].includes(objectFormat))
    throw new Error('Unsupported Git object format.');
  const rawOidLength = objectFormat === 'sha1' ? 20 : 32;
  const descriptions = all.length
    ? git(
        ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
        all.join('\n') + '\n',
      )
        .toString()
        .trim()
        .split('\n')
    : [];
  const objects = descriptions.map((line) => {
    const match = line.match(/^([0-9a-f]+) (blob|tree|commit|tag) (\d+)$/);
    if (!match) throw new Error('Missing or unsupported reachable Git object.');
    return { oid: match[1], type: match[2], size: Number(match[3]) };
  });
  const counts = {
    indexEntries: indexed.length,
    objects: objects.length,
    commits: 0,
    blobs: 0,
  };

  function inspectObject({ oid, type }, bytes) {
    const origin = index.has(oid)
      ? reachable.has(oid)
        ? 'index+history'
        : 'index'
      : 'history';
    const location = `${origin}:${type}:${oid}`;
    if (type === 'tree') {
      let offset = 0;
      let entry = 0;
      while (offset < bytes.length) {
        const space = bytes.indexOf(32, offset);
        const nul = bytes.indexOf(0, space + 1);
        if (
          space < offset ||
          nul < space ||
          nul + 1 + rawOidLength > bytes.length
        )
          throw new Error('Malformed Git tree.');
        const mode = bytes.subarray(offset, space).toString();
        const name = bytes.subarray(space + 1, nul).toString('utf8');
        if (forbiddenPath(name))
          add('FORBIDDEN_PATH', `${location}:entry-${entry}`);
        if (mode === '160000')
          add('UNSCANNED_SUBMODULE', `${location}:entry-${entry}`);
        for (const { category } of inspectContent(name))
          add(category, `${location}:entry-${entry}`);
        offset = nul + 1 + rawOidLength;
        entry++;
      }
      return;
    }
    if (type === 'commit') {
      counts.commits++;
      const headers = bytes.toString('utf8').split('\n\n', 1)[0];
      for (const field of ['author', 'committer']) {
        const line = headers
          .split('\n')
          .find((value) => value.startsWith(`${field} `));
        const address = line?.match(/<([^<>]*)> [-\d]+ [+-]\d{4}$/)?.[1];
        if (
          !address ||
          (!inherited.has(oid) &&
            address !== 'noreply@github.com' &&
            !/^[A-Za-z0-9][A-Za-z0-9+_.-]*@users\.noreply\.github\.com$/i.test(
              address,
            ))
        )
          add('NON_NOREPLY_COMMIT_EMAIL', `${location}:${field}`);
      }
    }
    if (type === 'blob') counts.blobs++;
    // Scan binary blobs too: embedded ASCII credentials must not be skipped.
    for (const { category, line } of inspectContent(bytes))
      add(category, `${location}:line-${line}`);
  }

  let batch = [];
  let batchSize = 0;
  function flush() {
    if (!batch.length) return;
    const data = git(
      ['cat-file', '--batch'],
      batch.map((o) => o.oid).join('\n') + '\n',
    );
    let offset = 0;
    for (const object of batch) {
      const newline = data.indexOf(10, offset);
      if (
        newline < 0 ||
        data.subarray(offset, newline).toString() !==
          `${object.oid} ${object.type} ${object.size}`
      )
        throw new Error('Unexpected Git batch response.');
      offset = newline + 1;
      if (
        offset + object.size >= data.length ||
        data[offset + object.size] !== 10
      )
        throw new Error('Truncated Git batch response.');
      inspectObject(object, data.subarray(offset, offset + object.size));
      offset += object.size + 1;
    }
    if (offset !== data.length)
      throw new Error('Unexpected trailing Git batch data.');
    batch = [];
    batchSize = 0;
  }
  for (const object of objects) {
    if (object.size > MAX_OBJECT) {
      add('OBJECT_TOO_LARGE_TO_SCAN', `object:${object.oid}`);
      continue;
    }
    if (batchSize + object.size > MAX_BATCH || batch.length >= 1000) flush();
    batch.push(object);
    batchSize += object.size;
  }
  flush();
  const unique = [
    ...new Map(
      findings.map((f) => [`${f.category}:${f.location}`, f]),
    ).values(),
  ];
  unique.sort(
    (a, b) =>
      a.category.localeCompare(b.category) ||
      a.location.localeCompare(b.location),
  );
  return { counts, findings: unique };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const args = process.argv.slice(2);
    if (args.length && (args.length !== 2 || args[0] !== '--repo'))
      throw new Error('Use privacy-check.mjs [--repo PATH].');
    const result = scanRepository(
      args[1] || resolve(import.meta.dirname, '..'),
    );
    console.log(JSON.stringify(result, null, 2));
    if (result.findings.length) process.exitCode = 1;
  } catch {
    console.error(
      'PRIVACY_CHECK_INCOMPLETE repository: unable to inspect all required Git data.',
    );
    process.exitCode = 2;
  }
}
