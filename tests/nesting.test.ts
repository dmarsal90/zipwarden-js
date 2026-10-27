import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../src/errors.js';
import { ZipWarden } from '../src/index.js';
import { buildZip } from './helpers/malicious-zips.js';
import { codeOf, withWorkDir } from './helpers/support.js';

/** A ZIP holding `levels` ZIPs one inside the other, around a single text file. */
function chain(levels: number): Buffer {
  let zip = buildZip([{ name: 'f.txt', data: Buffer.from('hello') }]);
  for (let i = 0; i < levels; i++) {
    zip = buildZip([{ name: 'in.zip', data: zip, deflate: false }]);
  }
  return zip;
}

async function extract(bytes: Buffer, limits: ConstructorParameters<typeof ZipWarden>[0]) {
  return withWorkDir(async (dir) => {
    const zip = join(dir, 'in.zip');
    await writeFile(zip, bytes);
    return codeOf(new ZipWarden(limits).extract(zip, join(dir, 'out')));
  });
}

describe('nested archives', () => {
  it.each([
    [0, 0, undefined],
    [1, 1, undefined],
    [2, 2, undefined],
    [1, 0, ErrorCode.NestedArchive],
    [2, 1, ErrorCode.NestedArchive],
  ])('%i levels with maxNestingDepth %i', async (levels, max, expected) => {
    expect(await extract(chain(levels), { limits: { maxNestingDepth: max } })).toBe(expected);
  });

  it('extracts the nested archive as a plain file and does not unpack it', async () => {
    await withWorkDir(async (dir) => {
      const zip = join(dir, 'in.zip');
      await writeFile(zip, chain(1));

      const result = await new ZipWarden({ limits: { maxNestingDepth: 1 } }).extract(
        zip,
        join(dir, 'out'),
      );

      expect(result.files).toEqual(['in.zip']);
    });
  });

  it('shares maxEntries across nesting levels', async () => {
    const inner = buildZip([
      { name: 'a.txt', data: Buffer.from('a') },
      { name: 'b.txt', data: Buffer.from('b') },
    ]);
    const outer = buildZip([
      { name: 'in.zip', data: inner, deflate: false },
      { name: 'c.txt', data: Buffer.from('c') },
    ]);

    expect(await extract(outer, { limits: { maxNestingDepth: 1, maxEntries: 4 } })).toBeUndefined();
    expect(await extract(outer, { limits: { maxNestingDepth: 1, maxEntries: 3 } })).toBe(
      ErrorCode.TooManyEntries,
    );
  });

  it('shares the total size budget across nesting levels', async () => {
    const inner = buildZip([{ name: 'b', data: Buffer.from('x'.repeat(6)) }]);
    const outer = buildZip([{ name: 'in.zip', data: inner, deflate: false }]);
    const exact = inner.length + 6;

    expect(
      await extract(outer, { limits: { maxNestingDepth: 1, maxTotalUncompressedSize: exact } }),
    ).toBeUndefined();
    expect(
      await extract(outer, { limits: { maxNestingDepth: 1, maxTotalUncompressedSize: exact - 1 } }),
    ).toBe(ErrorCode.TotalSizeExceeded);
  });

  it('applies the extension allowlist to nested files', async () => {
    const outer = buildZip([{ name: 'in.zip', data: chain(0), deflate: false }]);
    const limits = { maxNestingDepth: 1 };

    expect(
      await extract(outer, { limits, policy: { allowedExtensions: ['zip', 'txt'] } }),
    ).toBeUndefined();
    expect(await extract(outer, { limits, policy: { allowedExtensions: ['zip'] } })).toBe(
      ErrorCode.ExtensionNotAllowed,
    );
  });

  it('rejects a nested archive that is not a valid ZIP', async () => {
    const fake = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(40)]);
    const outer = buildZip([{ name: 'in.zip', data: fake, deflate: false }]);

    expect(await extract(outer, { limits: { maxNestingDepth: 1 } })).toBe(ErrorCode.InvalidArchive);
  });
});
