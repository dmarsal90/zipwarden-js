import { DEFAULT_LIMITS, type Limits } from './limits.js';
import { DEFAULT_POLICY, type Policy } from './policy.js';
import type { ExtractionResult, ZipWardenOptions } from './types.js';

export class ZipWarden {
  readonly limits: Readonly<Limits>;
  readonly policy: Readonly<Policy>;

  constructor(options: ZipWardenOptions = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...options.limits };
    this.policy = { ...DEFAULT_POLICY, ...options.policy };
  }

  /**
   * Extract `zipPath` into `destination`, or into a new private temporary
   * directory when `destination` is omitted. Failures reject with a ZipWardenError.
   */
  extract(_zipPath: string, _destination?: string): Promise<ExtractionResult> {
    return Promise.reject(new Error('Not implemented yet.'));
  }
}
