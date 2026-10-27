import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../../src/errors.js';
import { ZipWarden } from '../../src/index.js';
import { createMaliciousZips } from '../helpers/malicious-zips.js';
import { codeOf, withWorkDir } from '../helpers/support.js';

describe('size-mismatch', () => {
  it('rejects an entry whose real size exceeds its declared size with SIZE_MISMATCH', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        expect(await codeOf(new ZipWarden().extract(paths['false-size'], join(dir, 'out')))).toBe(
          ErrorCode.SizeMismatch,
        );
      });
    } finally {
      await cleanup();
    }
  });
});
