import type { Limits } from './limits.js';
import type { Policy } from './policy.js';

export interface ZipWardenOptions {
  limits?: Partial<Limits>;
  policy?: Partial<Policy>;
}

export interface ExtractionResult {
  /** Directory the archive was extracted into. */
  directory: string;
  /** Extracted file paths, relative to `directory`. */
  files: string[];
}
