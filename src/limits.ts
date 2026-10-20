/** Extraction limits. Defaults and their reasons: docs/SPEC.md, section 2. */
export interface Limits {
  maxArchiveSize: number;
  maxTotalUncompressedSize: number;
  maxEntrySize: number;
  maxEntries: number;
  maxRatio: number;
  maxDepth: number;
  maxNestingDepth: number;
  timeoutSeconds: number;
}

const MiB = 1024 * 1024;

export const DEFAULT_LIMITS: Readonly<Limits> = {
  maxArchiveSize: 100 * MiB,
  maxTotalUncompressedSize: 500 * MiB,
  maxEntrySize: 100 * MiB,
  maxEntries: 10_000,
  maxRatio: 100,
  maxDepth: 16,
  maxNestingDepth: 0,
  timeoutSeconds: 30,
};
