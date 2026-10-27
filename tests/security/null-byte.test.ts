import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../../src/errors.js';
import { ZipWarden } from '../../src/index.js';
import { createMaliciousZips } from '../helpers/malicious-zips.js';
import { codeOf, withWorkDir } from '../helpers/support.js';

describe('null-byte', () => {
  it('rejects names containing a NUL byte with NULL_BYTE', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        expect(await codeOf(new ZipWarden().extract(paths['null-byte'], join(dir, 'out')))).toBe(
          ErrorCode.NullByte,
        );
      });
    } finally {
      await cleanup();
    }
  });
});
