# ZipWarden specification (draft)

This document defines how ZipWarden behaves. The PHP and JavaScript
implementations must follow it exactly, so both files are kept identical.
Status: draft. Defaults and error codes may change before 1.0.

The words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Processing model

1. **Pre-scan.** Read the central directory without extracting anything. Check
   the archive size, entry count, and every entry name, type and declared size.
   Reject the whole archive on the first violation.
2. **Streaming extraction.** Extract each entry as a stream into an isolated
   staging directory. Count the bytes actually produced, not the sizes the
   archive claims. Stop as soon as a limit is crossed.
3. **Commit or discard.** If any step fails, delete everything written and
   throw one error carrying a code from section 5. If all steps pass, return
   the list of extracted files.

Declared sizes in the headers are untrusted. They are only used for the
pre-scan; the streaming counters are authoritative.

## 2. Default limits

| Option | Default | Why |
|---|---|---|
| `maxArchiveSize` | 100 MiB | A typical upload fits, and the read work stays bounded. |
| `maxTotalUncompressedSize` | 500 MiB | Large documents fit, and a bomb has a hard ceiling. |
| `maxEntrySize` | 100 MiB | No single file should dominate the total budget. |
| `maxEntries` | 10 000 | Covers real projects and stops inode exhaustion. |
| `maxRatio` | 100 | Ordinary text compresses 10:1 to 30:1; 100:1 leaves headroom. |
| `maxDepth` | 16 | Legitimate trees rarely go past 10 levels. |
| `maxNestingDepth` | 0 | Nested archives are rejected unless the caller opts in (max 2). |
| `timeoutSeconds` | 30 | Bounds CPU time spent on one archive. |

Rules:

- Sizes are in bytes. `maxRatio` is `uncompressed / compressed` per entry.
- The ratio check applies only to entries that produce more than 1 MiB, so
  tiny, highly repetitive files do not trigger false positives.
- `maxNestingDepth` of 0 means any entry that is itself a ZIP is rejected.
  With a value of N, archives nested up to N levels deep are scanned with the
  same limits, and the totals are shared across levels.
- `timeoutSeconds` is checked between chunks, so the real overrun is bounded
  by one chunk.

## 3. Policy (allowlist)

| Option | Default | Meaning |
|---|---|---|
| `allowedExtensions` | `[]` | Lowercase extensions without the dot. An empty list allows every extension. |

- The last extension of the final path segment is compared, case-insensitively.
  `report.pdf.exe` has the extension `exe`.
- A file with no extension is allowed only when the list is empty or contains
  the empty string.
- Directories are not checked against the list.
- Callers SHOULD set an explicit list. The empty default is a convenience, not
  a recommendation.

## 4. Rejection rules

An archive is rejected if any entry matches one of these rules.

### 4.1 Names

- The name contains a NUL byte (`\0`) anywhere.
- The name is empty, or contains a control character below `0x20`.
- The name is absolute: it starts with `/` or `\`, or with a drive prefix such
  as `C:`.
- After converting `\` to `/` and splitting on `/`, any segment is `..`.
- The name is not valid UTF-8 and is not flagged as CP437 by the archive.
- After normalisation, two entries map to the same path, compared
  case-insensitively.
- The depth, counted as the number of directory segments, exceeds `maxDepth`.
- The resolved destination path is not strictly inside the staging directory.
  This check always runs, even when the name looks harmless.

### 4.2 Entry types

- Symbolic links, detected from the Unix mode in the external attributes.
- Hard links, devices, FIFOs and sockets (any Unix type that is not a regular
  file or a directory).
- Encrypted entries, and multi-disk archives.

Extraction MUST NOT create symlinks and MUST NOT follow any that already exist
in the destination.

### 4.3 Sizes and structure

- The archive is larger than `maxArchiveSize`.
- There are more than `maxEntries` entries.
- A declared or actual entry size exceeds `maxEntrySize`.
- The running total of extracted bytes exceeds `maxTotalUncompressedSize`.
- An entry's ratio exceeds `maxRatio` (see section 2).
- The bytes produced differ from the declared uncompressed size, or the CRC-32
  does not match.
- An entry is a ZIP and `maxNestingDepth` allows no further nesting.
- Elapsed time exceeds `timeoutSeconds`.
- The extension is not in `allowedExtensions` (when the list is not empty).
- The central directory is missing, truncated or inconsistent with the local
  headers.

## 5. Error codes

Errors expose a stable string code. Messages are for humans and may change;
codes may not.

| Code | Raised when |
|---|---|
| `INVALID_ARCHIVE` | Unreadable, truncated or inconsistent archive. |
| `UNSUPPORTED_FEATURE` | Encrypted entry or multi-disk archive. |
| `PATH_TRAVERSAL` | A `..` segment, or a resolved path outside the destination. |
| `ABSOLUTE_PATH` | Leading slash, backslash or drive prefix. |
| `NULL_BYTE` | NUL byte in a name. |
| `INVALID_PATH` | Empty name, control characters, bad encoding. |
| `DUPLICATE_ENTRY` | Two entries resolve to the same path. |
| `SYMLINK` | Symbolic link entry. |
| `SPECIAL_FILE` | Hard link, device, FIFO or socket entry. |
| `ARCHIVE_TOO_LARGE` | Over `maxArchiveSize`. |
| `TOO_MANY_ENTRIES` | Over `maxEntries`. |
| `ENTRY_SIZE_EXCEEDED` | One entry over `maxEntrySize`. |
| `TOTAL_SIZE_EXCEEDED` | Total output over `maxTotalUncompressedSize`. |
| `RATIO_EXCEEDED` | Entry ratio over `maxRatio`. |
| `DEPTH_EXCEEDED` | Directory depth over `maxDepth`. |
| `NESTED_ARCHIVE` | Nested ZIP beyond `maxNestingDepth`. |
| `SIZE_MISMATCH` | Actual bytes or CRC-32 differ from the headers. |
| `TIMEOUT` | Over `timeoutSeconds`. |
| `EXTENSION_NOT_ALLOWED` | Extension outside the allowlist. |
| `DESTINATION_NOT_EMPTY` | The target directory already has content. |
| `IO_ERROR` | Filesystem or stream failure. |

When several rules match, the code reported is the first one hit in
processing order: pre-scan checks in central-directory order, then streaming
checks in entry order.

## 6. Destination rules

- Extraction targets one directory. If the caller gives none, the library
  creates a new private temporary directory with mode `0700`.
- A caller-supplied directory MUST be empty or absent; otherwise the error is
  `DESTINATION_NOT_EMPTY`. Existing files are never overwritten.
- Files are created with mode `0644` and directories with `0755`, whatever the
  archive says. Setuid, setgid and sticky bits are never applied.
- Every path is resolved and checked to be inside the destination before any
  write, and files are opened with exclusive creation.
- On failure, everything written is removed, including a temporary directory
  the library created.

## 7. Out of scope

Password-protected archives, creating archives, other formats (tar, 7z, rar),
and scanning file contents for malware.

## 8. Test requirements

Both implementations MUST pass the same scenarios, with fixtures generated at
test time (no binary fixtures in the repository):

- zip slip with `../`, an absolute path, and backslash separators
- a symbolic link entry
- a name containing a NUL byte
- a simple bomb (one entry with a very high ratio)
- a nested bomb (a ZIP inside a ZIP)
- an entry whose declared size is smaller than its real size
- limits at the boundary: exactly at the limit passes, one over fails
