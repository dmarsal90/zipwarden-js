import { ErrorCode, ZipWardenError } from './errors.js';

/** Validates and normalises entry names. See docs/SPEC.md, section 4.1. */

const utf8 = new TextDecoder('utf-8', { fatal: true });

export interface NormalizedName {
  /** Uses "/" and has no trailing slash. */
  path: string;
  isDirectory: boolean;
}

export function normalizeName(raw: Buffer, maxDepth: number): NormalizedName {
  // latin1 maps bytes 1:1, so the checks below cannot be fooled by decoding.
  const bytes = raw.toString('latin1');

  if (bytes.includes('\0')) throw new ZipWardenError(ErrorCode.NullByte);
  // eslint-disable-next-line no-control-regex
  if (bytes === '' || /[\x00-\x1f]/.test(bytes)) throw new ZipWardenError(ErrorCode.InvalidPath);
  if (/^[/\\]|^[A-Za-z]:/.test(bytes)) throw new ZipWardenError(ErrorCode.AbsolutePath);

  const slashed = bytes.replaceAll('\\', '/');
  if (slashed.split('/').includes('..')) throw new ZipWardenError(ErrorCode.PathTraversal);

  let name: string;
  try {
    name = utf8.decode(raw).replaceAll('\\', '/');
  } catch {
    // shortcut: names flagged as CP437 are rejected too; revisit if real archives need them.
    throw new ZipWardenError(ErrorCode.InvalidPath);
  }

  const isDirectory = name.endsWith('/');
  const segments = name.split('/').filter((s) => s !== '' && s !== '.');
  if (segments.length === 0) throw new ZipWardenError(ErrorCode.InvalidPath);
  if (segments.length - (isDirectory ? 0 : 1) > maxDepth) {
    throw new ZipWardenError(ErrorCode.DepthExceeded);
  }

  return { path: segments.join('/'), isDirectory };
}
