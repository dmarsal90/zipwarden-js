import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../../src/errors.js';
import { ZipWarden } from '../../src/index.js';
import { createMaliciousZips } from '../helpers/malicious-zips.js';
import { codeOf, withWorkDir } from '../helpers/support.js';

describe('zip-slip', () => {
  it.each([
    ['zip-slip', 'rejects entries with ../ segments', ErrorCode.PathTraversal],
    ['zip-slip-backslash', 'rejects backslash-separated traversal', ErrorCode.PathTraversal],
    ['absolute-path', 'rejects absolute paths', ErrorCode.AbsolutePath],
  ] as const)('%s: %s', async (fixture, _label, code) => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        expect(await codeOf(new ZipWarden().extract(paths[fixture], join(dir, 'out')))).toBe(code);
      });
    } finally {
      await cleanup();
    }
  });

  it('never writes any file outside the destination directory', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        const destination = join(dir, 'sub', 'out');
        await new ZipWarden().extract(paths['zip-slip'], destination).catch(() => undefined);

        expect(await readdir(dir)).toEqual([]);
      });
    } finally {
      await cleanup();
    }
  });
});
