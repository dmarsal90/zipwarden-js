import { chmod, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../src/errors.js';
import { ZipWarden } from '../src/index.js';
import { buildZip, type Entry } from './helpers/malicious-zips.js';
import { codeOf, withWorkDir } from './helpers/support.js';

const empty = Buffer.alloc(0);
const file = (name: string, data: Buffer | string = 'x', extra: Partial<Entry> = {}): Entry => ({
  name,
  data: Buffer.from(data),
  ...extra,
});

async function zipIn(dir: string, entries: Entry[]): Promise<string> {
  const path = join(dir, 'in.zip');
  await writeFile(path, buildZip(entries));
  return path;
}

describe('extract', () => {
  it('extracts files and directories with fixed modes', async () => {
    await withWorkDir(async (dir) => {
      const zip = await zipIn(dir, [
        file('docs/', empty),
        file('docs/a.txt', 'hello', { mode: 0o100777 }),
        file('stored.txt', 'plain', { deflate: false }),
        file('empty.txt', empty, { deflate: false }),
      ]);

      const result = await new ZipWarden().extract(zip, join(dir, 'out'));

      expect(result.directory).toBe(join(dir, 'out'));
      expect([...result.files].sort()).toEqual(['docs/a.txt', 'empty.txt', 'stored.txt']);
      expect(await readFile(join(dir, 'out/docs/a.txt'), 'utf8')).toBe('hello');
      expect(await readFile(join(dir, 'out/stored.txt'), 'utf8')).toBe('plain');
      expect((await stat(join(dir, 'out/docs/a.txt'))).mode & 0o7777).toBe(0o644);
      expect((await stat(join(dir, 'out/docs'))).mode & 0o7777).toBe(0o755);
      expect((await stat(join(dir, 'out'))).mode & 0o7777).toBe(0o755);
    });
  });

  it('creates implicit parent directories', async () => {
    await withWorkDir(async (dir) => {
      const result = await new ZipWarden().extract(
        await zipIn(dir, [file('a/b/c.txt')]),
        join(dir, 'out'),
      );

      expect(result.files).toEqual(['a/b/c.txt']);
      expect(await readFile(join(dir, 'out/a/b/c.txt'), 'utf8')).toBe('x');
    });
  });

  it('extracts into a private temporary directory by default', async () => {
    await withWorkDir(async (dir) => {
      const result = await new ZipWarden().extract(await zipIn(dir, [file('a.txt')]));

      expect(result.directory.startsWith(tmpdir())).toBe(true);
      expect((await stat(result.directory)).mode & 0o7777).toBe(0o700);
      expect(await readFile(join(result.directory, 'a.txt'), 'utf8')).toBe('x');
    });
  });

  it('accepts an existing empty destination and rejects anything else', async () => {
    await withWorkDir(async (dir) => {
      const zip = await zipIn(dir, [file('a.txt')]);
      const warden = new ZipWarden();

      await mkdir(join(dir, 'empty'));
      expect((await warden.extract(zip, join(dir, 'empty'))).files).toEqual(['a.txt']);

      await mkdir(join(dir, 'full'));
      await writeFile(join(dir, 'full/keep.txt'), 'mine');
      expect(await codeOf(warden.extract(zip, join(dir, 'full')))).toBe(
        ErrorCode.DestinationNotEmpty,
      );
      expect(await readFile(join(dir, 'full/keep.txt'), 'utf8')).toBe('mine');

      await writeFile(join(dir, 'plain'), 'a file');
      expect(await codeOf(warden.extract(zip, join(dir, 'plain')))).toBe(
        ErrorCode.DestinationNotEmpty,
      );
    });
  });

  it('keeps the mode of an existing destination', async () => {
    await withWorkDir(async (dir) => {
      await mkdir(join(dir, 'out'));
      await chmod(join(dir, 'out'), 0o750);

      await new ZipWarden().extract(await zipIn(dir, [file('a.txt')]), join(dir, 'out'));

      expect((await stat(join(dir, 'out'))).mode & 0o7777).toBe(0o750);
    });
  });

  it('removes everything written when a later entry fails', async () => {
    await withWorkDir(async (dir) => {
      const zip = await zipIn(dir, [
        file('ok.txt'),
        file('big.txt', 'A'.repeat(64), { declaredSize: 1 }),
      ]);

      expect(await codeOf(new ZipWarden().extract(zip, join(dir, 'out')))).toBe(
        ErrorCode.SizeMismatch,
      );
      expect((await readdir(dir)).sort()).toEqual(['in.zip']);
    });
  });

  it('accepts the total size exactly at the limit and rejects one byte less', async () => {
    await withWorkDir(async (dir) => {
      const zip = await zipIn(dir, [file('a', 'x'.repeat(6)), file('b', 'x'.repeat(4))]);

      const ok = await new ZipWarden({ limits: { maxTotalUncompressedSize: 10 } }).extract(
        zip,
        join(dir, 'ok'),
      );
      expect(ok.files).toHaveLength(2);

      const over = new ZipWarden({ limits: { maxTotalUncompressedSize: 9 } }).extract(
        zip,
        join(dir, 'over'),
      );
      expect(await codeOf(over)).toBe(ErrorCode.TotalSizeExceeded);
    });
  });

  it('rejects an entry whose real size passes the limit even if the header is below it', async () => {
    await withWorkDir(async (dir) => {
      const zip = await zipIn(dir, [file('a', 'x'.repeat(20), { declaredSize: 5 })]);
      const warden = new ZipWarden({ limits: { maxEntrySize: 10 } });

      expect(await codeOf(warden.extract(zip, join(dir, 'out')))).toBe(ErrorCode.EntrySizeExceeded);
    });
  });

  it('rejects a CRC-32 that does not match the content', async () => {
    await withWorkDir(async (dir) => {
      const zip = await zipIn(dir, [file('a', 'hello', { crc: 123 })]);

      expect(await codeOf(new ZipWarden().extract(zip, join(dir, 'out')))).toBe(
        ErrorCode.SizeMismatch,
      );
    });
  });

  it('aborts with TIMEOUT when the time budget is spent', async () => {
    await withWorkDir(async (dir) => {
      const warden = new ZipWarden({ limits: { timeoutSeconds: -1 } });

      expect(await codeOf(warden.extract(await zipIn(dir, [file('a')]), join(dir, 'out')))).toBe(
        ErrorCode.Timeout,
      );
    });
  });

  it('rejects a local header whose name differs from the central directory', async () => {
    await withWorkDir(async (dir) => {
      const bytes = buildZip([file('a.txt')]);
      bytes[30] = 'b'.charCodeAt(0); // first byte of the local header name
      const zip = join(dir, 'in.zip');
      await writeFile(zip, bytes);

      expect(await codeOf(new ZipWarden().extract(zip, join(dir, 'out')))).toBe(
        ErrorCode.InvalidArchive,
      );
    });
  });

  it('rejects compression methods other than stored and deflate', async () => {
    await withWorkDir(async (dir) => {
      const bytes = buildZip([file('a.txt')]);
      bytes.writeUInt16LE(12, bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])) + 10); // bzip2

      const zip = join(dir, 'in.zip');
      await writeFile(zip, bytes);

      expect(await codeOf(new ZipWarden().extract(zip, join(dir, 'out')))).toBe(
        ErrorCode.UnsupportedFeature,
      );
    });
  });

  it('rejects truncated compressed data as INVALID_ARCHIVE', async () => {
    await withWorkDir(async (dir) => {
      const bytes = buildZip([file('a.txt', 'hello world '.repeat(100))]);
      // Cut the deflate stream short, but keep the headers consistent with the file size.
      const central = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
      bytes.fill(0xff, 30 + 5 + 4, central - 4); // corrupt the deflate payload
      const zip = join(dir, 'in.zip');
      await writeFile(zip, bytes);

      expect(await codeOf(new ZipWarden().extract(zip, join(dir, 'out')))).toBe(
        ErrorCode.InvalidArchive,
      );
    });
  });
});
