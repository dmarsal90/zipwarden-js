/** Stable error codes. See docs/SPEC.md, section 5. */
export const ErrorCode = {
  InvalidArchive: 'INVALID_ARCHIVE',
  UnsupportedFeature: 'UNSUPPORTED_FEATURE',
  PathTraversal: 'PATH_TRAVERSAL',
  AbsolutePath: 'ABSOLUTE_PATH',
  NullByte: 'NULL_BYTE',
  InvalidPath: 'INVALID_PATH',
  DuplicateEntry: 'DUPLICATE_ENTRY',
  Symlink: 'SYMLINK',
  SpecialFile: 'SPECIAL_FILE',
  ArchiveTooLarge: 'ARCHIVE_TOO_LARGE',
  TooManyEntries: 'TOO_MANY_ENTRIES',
  EntrySizeExceeded: 'ENTRY_SIZE_EXCEEDED',
  TotalSizeExceeded: 'TOTAL_SIZE_EXCEEDED',
  RatioExceeded: 'RATIO_EXCEEDED',
  DepthExceeded: 'DEPTH_EXCEEDED',
  NestedArchive: 'NESTED_ARCHIVE',
  SizeMismatch: 'SIZE_MISMATCH',
  Timeout: 'TIMEOUT',
  ExtensionNotAllowed: 'EXTENSION_NOT_ALLOWED',
  DestinationNotEmpty: 'DESTINATION_NOT_EMPTY',
  IoError: 'IO_ERROR',
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export class ZipWardenError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'ZipWardenError';
    this.code = code;
  }
}
