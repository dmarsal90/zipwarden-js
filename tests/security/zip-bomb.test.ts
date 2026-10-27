import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../../src/errors.js';
import { ZipWarden } from '../../src/index.js';
import { createMaliciousZips } from '../helpers/malicious-zips.js';
import { codeOf, withWorkDir } from '../helpers/support.js';

describe('zip-bomb', () => {
  it('rejects a high-ratio entry with RATIO_EXCEEDED', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        expect(await codeOf(new ZipWarden().extract(paths.bomb, join(dir, 'out')))).toBe(
          ErrorCode.RatioExceeded,
        );
      });
    } finally {
      await cleanup();
    }
  });

  it('stops streaming as soon as the limit is crossed and removes partial output', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        // A permissive ratio lets the bomb reach the streaming counters.
        const warden = new ZipWarden({
          limits: { maxRatio: 1e9, maxTotalUncompressedSize: 1024 * 1024 },
        });

        expect(await codeOf(warden.extract(paths.bomb, join(dir, 'out')))).toBe(
          ErrorCode.TotalSizeExceeded,
        );
        expect(await readdir(dir)).toEqual([]);
      });
    } finally {
      await cleanup();
    }
  });

  it('rejects a nested archive with NESTED_ARCHIVE when maxNestingDepth is 0', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      await withWorkDir(async (dir) => {
        expect(await codeOf(new ZipWarden().extract(paths['nested-bomb'], join(dir, 'out')))).toBe(
          ErrorCode.NestedArchive,
        );
      });
    } finally {
      await cleanup();
    }
  });

  // Fixture: nested-bomb
  it.skip('shares the total size budget across nesting levels when nesting is allowed', () => {
    // pending: nested archive inspection is not implemented yet
  });
});
