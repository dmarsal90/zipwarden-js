import { describe, it } from 'vitest';

describe('zip-slip', () => {
  // Fixture: zip-slip
  it.skip('rejects entries with ../ segments with PATH_TRAVERSAL', () => {
    // pending: extraction is not implemented yet
  });

  // Fixture: zip-slip-backslash
  it.skip('rejects backslash-separated traversal with PATH_TRAVERSAL', () => {
    // pending: extraction is not implemented yet
  });

  // Fixture: absolute-path
  it.skip('rejects absolute paths with ABSOLUTE_PATH', () => {
    // pending: extraction is not implemented yet
  });

  // Fixture: zip-slip
  it.skip('never writes any file outside the destination directory', () => {
    // pending: extraction is not implemented yet
  });
});
