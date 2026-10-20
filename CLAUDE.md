# ZipWarden (JS)

Safe reading and extraction of untrusted ZIP archives (zip slip and zip bomb
protection) for Node.js. Behaviour is defined in `docs/SPEC.md`, which is
identical to the one in the `zipwarden-php` sibling project. Change both
together.

Status: scaffold only. Extraction logic is not implemented. `yauzl` is
installed for the future reader and is not used yet.

## Commands

- `pnpm install`
- `pnpm test` (Vitest)
- `pnpm lint` (ESLint + Prettier check) and `pnpm format` (fix)
- `pnpm typecheck` (tsc, strict)
- `pnpm build` (tsup: ESM + CJS + types in `dist/`)

## Conventions

- Node 20+, strict TypeScript, ESM source with `.js` import suffixes.
- Public API is exported only from `src/index.ts`; `package.json` `exports`
  must keep matching the files tsup emits.
- Never read a whole entry into memory; use streams.
- Errors are `ZipWardenError` carrying an `ErrorCode`. Codes are stable;
  messages are not.
- Tests build malicious ZIPs at runtime with `tests/helpers/malicious-zips.ts`.
  Do not commit binary ZIP files.
- Commits follow Conventional Commits.

## Hard rule

No extraction may write outside the destination directory. Resolve every path
and check it is inside the destination before writing, and never create or
follow symlinks. Any change that weakens this needs a test that proves it
still holds.
