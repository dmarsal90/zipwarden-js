import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ZipWardenError } from '../../src/errors.js';

/** The code of the ZipWardenError a promise rejects with, or undefined when it resolves. */
export async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ZipWardenError) return error.code;
    throw error;
  }
  return undefined;
}

/** Run `fn` with a new empty directory, removed afterwards. */
export async function withWorkDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'zipwarden-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
