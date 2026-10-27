# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Archive pre-scan: central directory parsing, path guard, entry type, size
  and entry count checks before any write.
- Streaming extraction into a staging directory, with byte counting, CRC-32
  and ratio checks, and cleanup on failure.
- Nested archive validation sharing the same limits (`maxNestingDepth`).

## [0.1.0-alpha.0] - 2026-10-20

Name reservation. Scaffold only: `extract()` is not implemented, do not use this version.

### Added

- Project scaffold: option types, error codes and a `ZipWarden` class with
  a placeholder `extract`. No extraction logic yet.
- Specification in `docs/SPEC.md`.
- Test setup, a malicious ZIP generator and pending security tests.
- CI workflow (lint, type check, tests, build).
