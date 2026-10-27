import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ErrorCode } from '../src/errors.js';
import { DEFAULT_LIMITS, type Limits } from '../src/limits.js';
import { DEFAULT_POLICY, type Policy } from '../src/policy.js';
import { scan } from '../src/scanner.js';
import { buildZip, type Entry } from './helpers/malicious-zips.js';
import { codeOf } from './helpers/support.js';

const FIFO = 0o010644;
const SOCKET = 0o140644;
const SYMLINK = 0o120777;
const empty = Buffer.alloc(0);

let dir: string;
let counter = 0;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'zipwarden-scan-'));
});
afterAll(() => rm(dir, { recursive: true, force: true }));

async function scanBytes(
  bytes: Buffer,
  limits: Partial<Limits> = {},
  policy: Partial<Policy> = {},
) {
  const path = join(dir, `${String(counter++)}.zip`);
  await writeFile(path, bytes);
  return scan(path, { ...DEFAULT_LIMITS, ...limits }, { ...DEFAULT_POLICY, ...policy });
}

const scanEntries = (entries: Entry[], limits?: Partial<Limits>, policy?: Partial<Policy>) =>
  scanBytes(buildZip(entries), limits, policy);

const file = (name: string, data: Buffer | string = 'x', extra: Partial<Entry> = {}): Entry => ({
  name,
  data: Buffer.from(data),
  ...extra,
});

describe('scanner', () => {
  it('returns normalised entries in central-directory order', async () => {
    const entries = await scanEntries([file('docs/', empty), file('docs/a.txt', 'hello')]);

    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ path: 'docs', isDirectory: true });
    expect(entries[1]).toMatchObject({ path: 'docs/a.txt', isDirectory: false, size: 5 });
  });

  it.each([
    ['zip slip', '../evil.txt', ErrorCode.PathTraversal],
    ['zip slip backslash', '..\\evil.txt', ErrorCode.PathTraversal],
    ['absolute path', '/tmp/evil.txt', ErrorCode.AbsolutePath],
    ['backslash absolute path', '\\evil.txt', ErrorCode.AbsolutePath],
    ['drive prefix', 'C:evil.txt', ErrorCode.AbsolutePath],
    ['nul byte', 'safe.txt\0.exe', ErrorCode.NullByte],
    ['control character', 'a\nb.txt', ErrorCode.InvalidPath],
    ['only dots and slashes', './', ErrorCode.InvalidPath],
  ])('rejects hostile name: %s', async (_label, name, code) => {
    expect(await codeOf(scanEntries([file(name)]))).toBe(code);
  });

  it('rejects names that are not valid UTF-8', async () => {
    const bytes = buildZip([file('abc.txt')]);
    // Turn the last name byte, in both the local and the central header, into a lone continuation byte.
    for (let i = 0; i < bytes.length - 3; i++) {
      if (bytes.toString('latin1', i, i + 3) === 'txt') bytes[i + 2] = 0x80;
    }

    expect(await codeOf(scanBytes(bytes))).toBe(ErrorCode.InvalidPath);
  });

  it('allows exactly maxDepth directory segments and rejects one more', async () => {
    expect(await scanEntries([file('a/b/c.txt')], { maxDepth: 2 })).toHaveLength(1);
    expect(await codeOf(scanEntries([file('a/b/c/d.txt')], { maxDepth: 2 }))).toBe(
      ErrorCode.DepthExceeded,
    );
  });

  it.each([
    ['symlink', SYMLINK, ErrorCode.Symlink],
    ['fifo', FIFO, ErrorCode.SpecialFile],
    ['socket', SOCKET, ErrorCode.SpecialFile],
  ])('rejects %s entries', async (_label, mode, code) => {
    expect(await codeOf(scanEntries([file('x', 'y', { mode })]))).toBe(code);
  });

  it('rejects encrypted entries with UNSUPPORTED_FEATURE', async () => {
    expect(await codeOf(scanEntries([file('a.txt', 'x', { flags: 0x1 })]))).toBe(
      ErrorCode.UnsupportedFeature,
    );
  });

  it('rejects multi-disk archives with UNSUPPORTED_FEATURE', async () => {
    const bytes = buildZip([file('a.txt')]);
    bytes.writeUInt16LE(1, bytes.length - 22 + 4); // number of this disk

    expect(await codeOf(scanBytes(bytes))).toBe(ErrorCode.UnsupportedFeature);
  });

  it('rejects duplicate entries ignoring case', async () => {
    expect(await codeOf(scanEntries([file('a.txt', '1'), file('A.TXT', '2')]))).toBe(
      ErrorCode.DuplicateEntry,
    );
  });

  it('accepts exactly maxEntries and rejects one more', async () => {
    const make = (n: number): Entry[] =>
      Array.from({ length: n }, (_, i) => file(`f${String(i)}.txt`));

    expect(await scanEntries(make(3), { maxEntries: 3 })).toHaveLength(3);
    expect(await codeOf(scanEntries(make(4), { maxEntries: 3 }))).toBe(ErrorCode.TooManyEntries);
  });

  it('accepts a declared entry size at maxEntrySize and rejects one more', async () => {
    const limits = { maxEntrySize: 10 };

    expect(await scanEntries([file('a', 'x'.repeat(10))], limits)).toHaveLength(1);
    expect(await codeOf(scanEntries([file('a', 'x'.repeat(11))], limits))).toBe(
      ErrorCode.EntrySizeExceeded,
    );
  });

  it('rejects a high declared ratio only above 1 MiB', async () => {
    const small = [file('a', Buffer.alloc(512 * 1024))];
    const bomb = [file('a', Buffer.alloc(20 * 1024 * 1024))];

    expect(await scanEntries(small, { maxRatio: 10 })).toHaveLength(1);
    expect(await codeOf(scanEntries(bomb))).toBe(ErrorCode.RatioExceeded);
  });

  it('accepts an archive exactly at maxArchiveSize and rejects one byte more', async () => {
    const bytes = buildZip([file('a')]);

    expect(await scanBytes(bytes, { maxArchiveSize: bytes.length })).toHaveLength(1);
    expect(await codeOf(scanBytes(bytes, { maxArchiveSize: bytes.length - 1 }))).toBe(
      ErrorCode.ArchiveTooLarge,
    );
  });

  it('applies the extension allowlist to files but not directories', async () => {
    const policy = { allowedExtensions: ['txt'] };

    expect(
      await scanEntries([file('a.exe/', empty), file('a.exe/NOTE.TXT')], {}, policy),
    ).toHaveLength(2);
    expect(await codeOf(scanEntries([file('report.pdf.exe')], {}, policy))).toBe(
      ErrorCode.ExtensionNotAllowed,
    );
    expect(await codeOf(scanEntries([file('Makefile')], {}, policy))).toBe(
      ErrorCode.ExtensionNotAllowed,
    );
    expect(await scanEntries([file('Makefile')], {}, { allowedExtensions: [''] })).toHaveLength(1);
  });

  it('rejects garbage and truncated archives as INVALID_ARCHIVE', async () => {
    const valid = buildZip([file('a')]);

    expect(await codeOf(scanBytes(Buffer.from('not a zip at all, but long enough')))).toBe(
      ErrorCode.InvalidArchive,
    );
    expect(await codeOf(scanBytes(valid.subarray(0, valid.length - 10)))).toBe(
      ErrorCode.InvalidArchive,
    );
  });

  it('ignores an end record hidden inside the archive comment', async () => {
    const fake = Buffer.alloc(22);
    fake.writeUInt32LE(0x06054b50, 0);
    fake.writeUInt16LE(100, 20); // claims a comment that runs past the end of the file
    const bytes = buildZip([file('a')]);
    bytes.writeUInt16LE(fake.length, bytes.length - 2); // real comment length
    const withComment = Buffer.concat([bytes, fake]);

    expect(await scanBytes(withComment)).toHaveLength(1);
  });

  it('rejects a missing file or a directory as IO_ERROR', async () => {
    const limits = { ...DEFAULT_LIMITS };

    expect(await codeOf(scan('/nonexistent/x.zip', limits, DEFAULT_POLICY))).toBe(
      ErrorCode.IoError,
    );
    expect(await codeOf(scan(dir, limits, DEFAULT_POLICY))).toBe(ErrorCode.IoError);
  });
});
