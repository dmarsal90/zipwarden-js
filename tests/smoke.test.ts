import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { DEFAULT_LIMITS, DEFAULT_POLICY, ZipWarden } from '../src/index.js';
import { createMaliciousZips } from './helpers/malicious-zips.js';

describe('smoke', () => {
  it('builds with the documented default limits', () => {
    const warden = new ZipWarden();

    expect(warden.limits).toEqual(DEFAULT_LIMITS);
    expect(warden.limits.maxRatio).toBe(100);
    expect(warden.limits.maxNestingDepth).toBe(0);
    expect(warden.policy).toEqual(DEFAULT_POLICY);
  });

  it('merges partial options over the defaults', () => {
    const warden = new ZipWarden({ limits: { maxEntries: 5 } });

    expect(warden.limits.maxEntries).toBe(5);
    expect(warden.limits.maxDepth).toBe(DEFAULT_LIMITS.maxDepth);
  });

  it('generates every malicious fixture as a ZIP-shaped file', async () => {
    const { paths, cleanup } = await createMaliciousZips();
    try {
      expect(Object.keys(paths)).toHaveLength(8);
      for (const path of Object.values(paths)) {
        const bytes = await readFile(path);
        expect(bytes.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
      }
    } finally {
      await cleanup();
    }
  });
});
