import { chmod, lstat, mkdir, mkdtemp, readdir, realpath, rename, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { ErrorCode, ZipWardenError } from './errors.js';
import { Extraction, toZipWardenError } from './extraction.js';
import { DEFAULT_LIMITS, type Limits } from './limits.js';
import { DEFAULT_POLICY, type Policy } from './policy.js';
import { openArchive, scanArchive } from './scanner.js';
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
  async extract(zipPath: string, destination?: string): Promise<ExtractionResult> {
    const { handle, size } = await openArchive(zipPath, this.limits);

    try {
      const entries = await scanArchive(handle, size, this.limits, this.policy);
      const { work, final } =
        destination === undefined
          ? { work: await createTemporaryDirectory(), final: undefined }
          : await createStagingDirectory(destination);

      try {
        const files = await new Extraction(
          this.limits,
          this.policy,
          await realpath(work),
          handle,
          size,
        ).run(entries);

        if (final !== undefined) {
          // shortcut: renaming over the empty destination replaces the directory itself, so its owner and group are lost (the mode is kept) and POSIX rename semantics are required; revisit for Windows.
          const existing = await lstat(final).catch(() => undefined);
          await chmod(work, existing ? existing.mode & 0o7777 : 0o755);
          await rename(work, final);
        }
        return { directory: final ?? work, files };
      } catch (error) {
        await rm(work, { recursive: true, force: true });
        throw toZipWardenError(error);
      }
    } finally {
      await handle.close();
    }
  }
}

async function createTemporaryDirectory(): Promise<string> {
  try {
    return await mkdtemp(join(tmpdir(), 'zipwarden-'));
  } catch {
    throw new ZipWardenError(ErrorCode.IoError);
  }
}

/**
 * Validates the destination (absent or empty) and creates a private staging
 * directory next to it, so the final rename stays on one filesystem.
 */
async function createStagingDirectory(
  destination: string,
): Promise<{ work: string; final: string }> {
  const name = basename(destination);
  if (['', '.', '..'].includes(name)) throw new ZipWardenError(ErrorCode.IoError);

  try {
    const parent = await realpath(dirname(destination));
    const final = join(parent, name);

    const info = await lstat(final).catch(() => undefined);
    if (info?.isSymbolicLink() || (info && !info.isDirectory())) {
      throw new ZipWardenError(ErrorCode.DestinationNotEmpty);
    }
    if (info && (await readdir(final)).length > 0)
      throw new ZipWardenError(ErrorCode.DestinationNotEmpty);

    const work = join(parent, `.zipwarden-${randomBytes(8).toString('hex')}`);
    await mkdir(work, { mode: 0o700 });
    return { work, final };
  } catch (error) {
    throw toZipWardenError(error);
  }
}
