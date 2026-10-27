import { open, type FileHandle } from 'node:fs/promises';
import { readCentralDirectory } from './central-directory.js';
import { ErrorCode, ZipWardenError } from './errors.js';
import type { Limits } from './limits.js';
import { normalizeName } from './path-guard.js';
import { allowsPath, type Policy } from './policy.js';

/**
 * Pre-scan: checks the central directory without extracting anything.
 * See docs/SPEC.md, section 1 step 1 and section 4.
 */

const UNIX = 3;
const TYPE_MASK = 0o170000;
const REGULAR = 0o100000;
const DIRECTORY = 0o040000;
const SYMLINK = 0o120000;
const FLAG_ENCRYPTED = 0x1;
const FLAG_STRONG_ENCRYPTION = 0x40;
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;

/** The ratio check only applies to entries that produce more than this. */
export const RATIO_MIN_BYTES = 1024 * 1024;

/** An entry that passed the pre-scan. Sizes and CRC come from the headers and are untrusted. */
export interface ScannedEntry {
  index: number;
  path: string;
  isDirectory: boolean;
  size: number;
  compressedSize: number;
  crc: number;
  method: number;
  /** Offset of the local header. */
  offset: number;
  /** Raw name from the central directory, to compare with the local header. */
  nameBytes: Buffer;
}

function checkType(versionMadeBy: number, flags: number, externalAttributes: number): void {
  if (flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION)) {
    throw new ZipWardenError(ErrorCode.UnsupportedFeature, 'Encrypted entries are not supported.');
  }
  const type = versionMadeBy >> 8 === UNIX ? (externalAttributes >>> 16) & TYPE_MASK : 0;
  if (type === SYMLINK) throw new ZipWardenError(ErrorCode.Symlink);
  if (type !== 0 && type !== REGULAR && type !== DIRECTORY) {
    throw new ZipWardenError(ErrorCode.SpecialFile);
  }
}

/** Declared sizes only give an early rejection; streaming counters are authoritative. */
function checkSizes(size: number, compressedSize: number, limits: Limits): void {
  if (size > limits.maxEntrySize) throw new ZipWardenError(ErrorCode.EntrySizeExceeded);
  if (size > RATIO_MIN_BYTES && (compressedSize === 0 || size / compressedSize > limits.maxRatio)) {
    throw new ZipWardenError(ErrorCode.RatioExceeded);
  }
}

/** Open the archive and check its size. Callers close the handle. */
export async function openArchive(
  zipPath: string,
  limits: Limits,
): Promise<{ handle: FileHandle; size: number }> {
  let handle: FileHandle;
  try {
    handle = await open(zipPath, 'r');
  } catch {
    throw new ZipWardenError(ErrorCode.IoError);
  }

  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new ZipWardenError(ErrorCode.IoError);
    if (info.size > limits.maxArchiveSize) throw new ZipWardenError(ErrorCode.ArchiveTooLarge);
    return { handle, size: info.size };
  } catch (error) {
    await handle.close();
    throw error instanceof ZipWardenError ? error : new ZipWardenError(ErrorCode.IoError);
  }
}

/** Reject the whole archive on the first violation, in central-directory order. */
export async function scanArchive(
  handle: FileHandle,
  size: number,
  limits: Limits,
  policy: Policy,
): Promise<ScannedEntry[]> {
  try {
    const raw = await readCentralDirectory(handle, size, limits.maxEntries);
    const entries: ScannedEntry[] = [];
    // shortcut: case folding uses toLowerCase; a collision it misses still fails later because files are created exclusively.
    const seen = new Set<string>();

    raw.forEach((entry, index) => {
      const { path, isDirectory } = normalizeName(entry.name, limits.maxDepth);
      checkType(entry.versionMadeBy, entry.flags, entry.externalAttributes);

      const key = path.toLowerCase();
      if (seen.has(key)) throw new ZipWardenError(ErrorCode.DuplicateEntry);
      seen.add(key);

      if (!isDirectory) {
        if (!allowsPath(policy, path)) throw new ZipWardenError(ErrorCode.ExtensionNotAllowed);
        checkSizes(entry.size, entry.compressedSize, limits);
        // shortcut: only stored and deflate entries are read; other methods are rejected, revisit if real archives need them.
        if (entry.method !== METHOD_STORED && entry.method !== METHOD_DEFLATE) {
          throw new ZipWardenError(ErrorCode.UnsupportedFeature, 'Unsupported compression method.');
        }
      }

      entries.push({
        index,
        path,
        isDirectory,
        size: entry.size,
        compressedSize: entry.compressedSize,
        crc: entry.crc,
        method: entry.method,
        offset: entry.offset,
        nameBytes: entry.name,
      });
    });

    return entries;
  } catch (error) {
    throw error instanceof ZipWardenError ? error : new ZipWardenError(ErrorCode.IoError);
  }
}

/** Pre-scan only: validates an archive without extracting anything. */
export async function scan(
  zipPath: string,
  limits: Limits,
  policy: Policy,
): Promise<ScannedEntry[]> {
  const { handle, size } = await openArchive(zipPath, limits);
  try {
    return await scanArchive(handle, size, limits, policy);
  } finally {
    await handle.close();
  }
}
