import { createWriteStream } from 'node:fs';
import { chmod, lstat, mkdir, realpath, type FileHandle } from 'node:fs/promises';
import { join, sep } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { crc32, createInflateRaw } from 'node:zlib';
import { readAt } from './central-directory.js';
import { ErrorCode, ZipWardenError } from './errors.js';
import type { Limits } from './limits.js';
import { RATIO_MIN_BYTES, type ScannedEntry } from './scanner.js';

/**
 * Streams the scanned entries into a fresh directory. One instance per
 * extraction: it holds the running totals. See docs/SPEC.md, section 1 step 2.
 */

const SIG_LOCAL = 0x04034b50;
const LOCAL_HEADER_SIZE = 30;
const METHOD_DEFLATE = 8;

/** Map whatever a stream or the filesystem threw to a stable error. */
export function toZipWardenError(error: unknown): ZipWardenError {
  if (error instanceof ZipWardenError) return error;
  const code = (error as { code?: unknown } | null)?.code;
  // zlib reports corrupt or truncated data with Z_* codes.
  if (typeof code === 'string' && code.startsWith('Z_'))
    return new ZipWardenError(ErrorCode.InvalidArchive);
  return new ZipWardenError(ErrorCode.IoError);
}

export class Extraction {
  private readonly deadline: number;
  private total = 0;
  private readonly files: string[] = [];

  /** @param root Existing, empty directory (resolved) that only this extraction writes to. */
  constructor(
    private readonly limits: Limits,
    private readonly root: string,
    private readonly handle: FileHandle,
    private readonly fileSize: number,
  ) {
    this.deadline = performance.now() + limits.timeoutSeconds * 1000;
  }

  async run(entries: ScannedEntry[]): Promise<string[]> {
    for (const entry of entries) {
      this.checkTime();
      if (entry.isDirectory) await this.ensureDirectory(entry.path);
      else await this.writeFile(entry);
    }
    return this.files;
  }

  private async writeFile(entry: ScannedEntry): Promise<void> {
    const slash = entry.path.lastIndexOf('/');
    const directory =
      slash === -1 ? this.root : await this.ensureDirectory(entry.path.slice(0, slash));
    const target = join(directory, entry.path.slice(slash + 1));

    const input = await this.openData(entry);
    // Exclusive creation: fails on any existing file or link, never follows one.
    const output = createWriteStream(target, { flags: 'wx', mode: 0o644 });
    const stages: (NodeJS.ReadableStream | NodeJS.ReadWriteStream | NodeJS.WritableStream)[] = [
      input,
    ];
    if (entry.method === METHOD_DEFLATE) stages.push(createInflateRaw());
    stages.push(this.meter(entry), output);

    await pipeline(stages);
    await chmod(target, 0o644);
    this.files.push(entry.path);
  }

  /** Check the local header against the central directory and return the compressed bytes. */
  private async openData(entry: ScannedEntry): Promise<Readable> {
    const header = await readAt(this.handle, entry.offset, LOCAL_HEADER_SIZE);
    if (header.readUInt32LE(0) !== SIG_LOCAL) throw new ZipWardenError(ErrorCode.InvalidArchive);

    const nameLength = header.readUInt16LE(26);
    const extraLength = header.readUInt16LE(28);
    const name = await readAt(this.handle, entry.offset + LOCAL_HEADER_SIZE, nameLength);
    if (!name.equals(entry.nameBytes)) throw new ZipWardenError(ErrorCode.InvalidArchive);

    const start = entry.offset + LOCAL_HEADER_SIZE + nameLength + extraLength;
    if (start + entry.compressedSize > this.fileSize)
      throw new ZipWardenError(ErrorCode.InvalidArchive);
    if (entry.compressedSize === 0) return Readable.from([]);
    return this.handle.createReadStream({
      start,
      end: start + entry.compressedSize - 1,
      autoClose: false,
    });
  }

  /**
   * Counts the bytes actually produced; the sizes in the headers are not trusted.
   * Every limit is checked before the chunk is written, so the output never passes it.
   */
  private meter(entry: ScannedEntry): Transform {
    let produced = 0;
    let crc = 0;
    let head = Buffer.alloc(0);

    return new Transform({
      transform: (chunk: Buffer, _encoding, callback) => {
        try {
          this.checkTime();
          produced += chunk.length;
          this.total += chunk.length;

          if (produced > this.limits.maxEntrySize)
            throw new ZipWardenError(ErrorCode.EntrySizeExceeded);
          if (this.total > this.limits.maxTotalUncompressedSize) {
            throw new ZipWardenError(ErrorCode.TotalSizeExceeded);
          }
          if (
            produced > RATIO_MIN_BYTES &&
            (entry.compressedSize === 0 || produced / entry.compressedSize > this.limits.maxRatio)
          ) {
            throw new ZipWardenError(ErrorCode.RatioExceeded);
          }
          if (produced > entry.size) throw new ZipWardenError(ErrorCode.SizeMismatch);

          if (head.length < 4) {
            head = Buffer.concat([head, chunk.subarray(0, 4 - head.length)]);
            if (head.length === 4 && isZipSignature(head) && this.limits.maxNestingDepth <= 0) {
              throw new ZipWardenError(ErrorCode.NestedArchive);
            }
          }

          crc = crc32(chunk, crc);
          callback(null, chunk);
        } catch (error) {
          callback(toZipWardenError(error));
        }
      },
      flush: (callback) => {
        if (produced !== entry.size || crc !== entry.crc) {
          callback(new ZipWardenError(ErrorCode.SizeMismatch));
        } else {
          callback();
        }
      },
    });
  }

  /**
   * Creates the directory one segment at a time and returns its resolved path.
   * Nothing in the staging tree may be a link, and the result must stay inside the root.
   */
  private async ensureDirectory(relative: string): Promise<string> {
    let current = this.root;

    for (const segment of relative.split('/')) {
      current = join(current, segment);
      const info = await lstat(current).catch(() => undefined);

      if (info?.isSymbolicLink()) throw new ZipWardenError(ErrorCode.PathTraversal);
      if (info === undefined) {
        await mkdir(current, { mode: 0o755 });
        await chmod(current, 0o755);
      } else if (!info.isDirectory()) {
        throw new ZipWardenError(ErrorCode.IoError);
      }
    }

    const resolved = await realpath(current);
    if (!(resolved + sep).startsWith(this.root + sep))
      throw new ZipWardenError(ErrorCode.PathTraversal);
    return resolved;
  }

  private checkTime(): void {
    if (performance.now() > this.deadline) throw new ZipWardenError(ErrorCode.Timeout);
  }
}

function isZipSignature(head: Buffer): boolean {
  const signature = head.readUInt32LE(0);
  return signature === SIG_LOCAL || signature === 0x06054b50;
}
