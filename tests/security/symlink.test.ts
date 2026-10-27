import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../../src/errors.js';
import { ZipWarden } from '../../src/index.js';
import { createMaliciousZips } from '../helpers/malicious-zips.js';
import { codeOf, withWorkDir } from '../helpers/support.js';

describe('symlink', () => {
  it('rejects symbolic link entries with SYMLINK', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        expect(await codeOf(new ZipWarden().extract(paths.symlink, join(dir, 'out')))).toBe(
          ErrorCode.Symlink,
        );
      });
    } finally {
      await cleanup();
    }
  });

  it('never creates a symlink in the destination', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        await new ZipWarden().extract(paths.symlink, join(dir, 'out')).catch(() => undefined);

        expect(await readdir(dir)).toEqual([]);
      });
    } finally {
      await cleanup();
    }
  });
});
