import type { FileHandle } from 'node:fs/promises';
import { ErrorCode, ZipWardenError } from './errors.js';

/**
 * Reads the raw central directory. Entry names are kept as bytes because the
 * name rules of docs/SPEC.md section 4.1 must run on what the archive says,
 * not on a decoded or normalised copy.
 */

const EOCD_SIZE = 22;
const MAX_COMMENT = 0xffff;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const ZIP64_EXTRA_ID = 0x0001;
const MAX_32 = 0xffffffff;

export interface RawEntry {
  name: Buffer;
  /** General purpose bit flags. */
  flags: number;
  /** Compression method. */
  method: number;
  versionMadeBy: number;
  externalAttributes: number;
  crc: number;
  compressedSize: number;
  size: number;
  /** Offset of the local header. */
  offset: number;
}

const invalid = (): ZipWardenError => new ZipWardenError(ErrorCode.InvalidArchive);

export async function readAt(
  handle: FileHandle,
  position: number,
  length: number,
): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  if (bytesRead !== length) throw invalid();
  return buffer;
}

function u64(buffer: Buffer, position: number): number {
  const value = buffer.readBigUInt64LE(position);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw invalid();
  return Number(value);
}

interface Location {
  count: number;
  offset: number;
  size: number;
}

async function locate(handle: FileHandle, fileSize: number): Promise<Location> {
  const tailLength = Math.min(fileSize, EOCD_SIZE + MAX_COMMENT);
  if (tailLength < EOCD_SIZE) throw invalid();
  const tail = await readAt(handle, fileSize - tailLength, tailLength);

  // Only an end record whose comment reaches the end of the file counts, so a
  // fake record hidden inside a comment cannot be picked.
  let position = tail.length - EOCD_SIZE;
  for (; position >= 0; position--) {
    if (
      tail.readUInt32LE(position) === SIG_EOCD &&
      position + EOCD_SIZE + tail.readUInt16LE(position + 20) === tail.length
    ) {
      break;
    }
  }
  if (position < 0) throw invalid();

  if (tail.readUInt16LE(position + 4) !== 0 || tail.readUInt16LE(position + 6) !== 0) {
    throw new ZipWardenError(
      ErrorCode.UnsupportedFeature,
      'Multi-disk archives are not supported.',
    );
  }
  const count = tail.readUInt16LE(position + 10);
  if (tail.readUInt16LE(position + 8) !== count) throw invalid();
  const size = tail.readUInt32LE(position + 12);
  const offset = tail.readUInt32LE(position + 16);

  if (count !== 0xffff && size !== MAX_32 && offset !== MAX_32) return { count, offset, size };
  return locateZip64(handle, fileSize, tail, position);
}

async function locateZip64(
  handle: FileHandle,
  fileSize: number,
  tail: Buffer,
  eocdPosition: number,
): Promise<Location> {
  if (eocdPosition < 20 || tail.readUInt32LE(eocdPosition - 20) !== SIG_ZIP64_LOCATOR)
    throw invalid();
  const recordOffset = u64(tail, eocdPosition - 12);
  if (recordOffset + 56 > fileSize) throw invalid();

  const record = await readAt(handle, recordOffset, 56);
  if (record.readUInt32LE(0) !== SIG_ZIP64_EOCD) throw invalid();
  if (record.readUInt32LE(16) !== 0 || record.readUInt32LE(20) !== 0) {
    throw new ZipWardenError(
      ErrorCode.UnsupportedFeature,
      'Multi-disk archives are not supported.',
    );
  }
  return { count: u64(record, 32), size: u64(record, 40), offset: u64(record, 48) };
}

/** Sizes and offset that did not fit in 32 bits live in the zip64 extra field. */
function applyZip64Extra(extra: Buffer, entry: RawEntry): void {
  let position = 0;
  while (position + 4 <= extra.length) {
    const id = extra.readUInt16LE(position);
    const length = extra.readUInt16LE(position + 2);
    const start = position + 4;
    if (start + length > extra.length) throw invalid();
    if (id === ZIP64_EXTRA_ID) {
      let cursor = start;
      const next = (): number => {
        if (cursor + 8 > start + length) throw invalid();
        const value = u64(extra, cursor);
        cursor += 8;
        return value;
      };
      if (entry.size === MAX_32) entry.size = next();
      if (entry.compressedSize === MAX_32) entry.compressedSize = next();
      if (entry.offset === MAX_32) entry.offset = next();
      return;
    }
    position = start + length;
  }
}

/**
 * Read every central directory entry, in order. Rejects with TOO_MANY_ENTRIES
 * before reading them when the end record already declares more than `maxEntries`.
 */
export async function readCentralDirectory(
  handle: FileHandle,
  fileSize: number,
  maxEntries: number,
): Promise<RawEntry[]> {
  const { count, offset, size } = await locate(handle, fileSize);
  if (count > maxEntries) throw new ZipWardenError(ErrorCode.TooManyEntries);
  if (offset + size > fileSize || count * 46 > size) throw invalid();

  const directory = await readAt(handle, offset, size);
  const entries: RawEntry[] = [];
  let position = 0;

  for (let i = 0; i < count; i++) {
    if (position + 46 > directory.length || directory.readUInt32LE(position) !== SIG_CENTRAL) {
      throw invalid();
    }
    const nameLength = directory.readUInt16LE(position + 28);
    const extraLength = directory.readUInt16LE(position + 30);
    const commentLength = directory.readUInt16LE(position + 32);
    const nameStart = position + 46;
    const extraStart = nameStart + nameLength;
    const next = extraStart + extraLength + commentLength;
    if (next > directory.length) throw invalid();

    const entry: RawEntry = {
      name: directory.subarray(nameStart, extraStart),
      versionMadeBy: directory.readUInt16LE(position + 4),
      flags: directory.readUInt16LE(position + 8),
      method: directory.readUInt16LE(position + 10),
      crc: directory.readUInt32LE(position + 16),
      compressedSize: directory.readUInt32LE(position + 20),
      size: directory.readUInt32LE(position + 24),
      externalAttributes: directory.readUInt32LE(position + 38),
      offset: directory.readUInt32LE(position + 42),
    };
    applyZip64Extra(directory.subarray(extraStart, extraStart + extraLength), entry);
    entries.push(entry);
    position = next;
  }

  return entries;
}
