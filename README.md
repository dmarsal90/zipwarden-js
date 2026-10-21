# ZipWarden for Node.js

[![npm](https://img.shields.io/npm/v/zipwarden/alpha?label=npm)](https://www.npmjs.com/package/zipwarden)

Safe ZIP reading and extraction. ZipWarden opens untrusted archives without
letting them write outside the target directory or exhaust your disk, memory
or CPU.

> **Status: in development.** Only the project structure, the specification and
> pending tests exist. The extraction logic is not implemented yet, so do not
> use this package to handle untrusted files. The alpha on npm is a placeholder for the structure only.

## What it will do

- Reject zip slip: `../` segments, absolute paths, symbolic links and NUL bytes
  in names.
- Reject zip bombs: limits on compressed and uncompressed size, entry count,
  compression ratio, directory depth, nested archives and elapsed time.
- Extract as a stream into an isolated temporary directory, with an optional
  allowlist of file extensions.
- Work with any framework. ESM and CommonJS builds ship with type definitions.

The exact behaviour, default limits and error codes are in
[docs/SPEC.md](docs/SPEC.md). The [PHP package](https://github.com/dmarsal90/zipwarden-php)
follows the same specification.

## Planned installation

```bash
pnpm add zipwarden
# or: npm install zipwarden
```

Requires Node.js 20+. Tested on 20 and 22. ESM and CommonJS.
<!-- TODO: confirm the npm package name before publishing. -->

## Planned usage (draft API)

This API is a proposal and may change.

```ts
import { ZipWarden, ZipWardenError, ErrorCode } from 'zipwarden';

const warden = new ZipWarden({
  limits: { maxTotalUncompressedSize: 50 * 1024 * 1024 },
  policy: { allowedExtensions: ['pdf', 'png', 'jpg'] },
});

try {
  const result = await warden.extract('/path/to/upload.zip');
  // result.directory is a private temporary directory
  // result.files lists what was extracted
} catch (error) {
  if (error instanceof ZipWardenError && error.code === ErrorCode.PathTraversal) {
    // reject the upload
  }
  throw error;
}
```

CommonJS works too: `const { ZipWarden } = require('zipwarden');`

## Threats covered

| Threat               | Example                            | Planned defence                                                   | Error code              |
| -------------------- | ---------------------------------- | ----------------------------------------------------------------- | ----------------------- |
| Zip slip             | `../../etc/cron.d/x`               | Reject `..`; check the resolved path stays inside the destination | `PATH_TRAVERSAL`        |
| Absolute path        | `/var/www/shell.js`                | Reject leading `/`, `\` and drive prefixes                        | `ABSOLUTE_PATH`         |
| NUL byte in name     | `safe.txt\0.js`                    | Reject any NUL byte                                               | `NULL_BYTE`             |
| Symlink escape       | `link -> /etc/passwd`              | Reject symlinks; never create or follow them                      | `SYMLINK`               |
| Simple zip bomb      | 1 entry, 20 MiB of zeros in 20 KiB | Count real output bytes; cap the ratio                            | `RATIO_EXCEEDED`        |
| Nested zip bomb      | A bomb inside a ZIP                | Reject nesting by default; share the budget if allowed            | `NESTED_ARCHIVE`        |
| Lying size headers   | Declares 1 byte, inflates to 1 GiB | Trust only streamed byte counts                                   | `SIZE_MISMATCH`         |
| Too many entries     | 10 million empty files             | Cap the entry count                                               | `TOO_MANY_ENTRIES`      |
| Deep directories     | 5000 nested folders                | Cap the depth                                                     | `DEPTH_EXCEEDED`        |
| Slow archives        | Crafted to burn CPU                | Time limit checked between chunks                                 | `TIMEOUT`               |
| Dangerous file types | `.sh`, `.exe`                      | Optional extension allowlist                                      | `EXTENSION_NOT_ALLOWED` |

## Development

```bash
pnpm install
pnpm test        # Vitest
pnpm lint        # ESLint + Prettier check; pnpm format fixes
pnpm typecheck   # tsc --noEmit
pnpm build       # tsup -> dist (ESM, CJS, types)
```

The planned ZIP reader is [yauzl](https://github.com/thejoshwolfe/yauzl), which
is installed but not used yet.

## License

MIT. See [LICENSE](LICENSE).
