import { describe, it } from 'vitest';

describe('zip-bomb', () => {
  // Fixture: bomb
  it.skip('rejects a high-ratio entry with RATIO_EXCEEDED', () => {
    // pending: extraction is not implemented yet
  });

  // Fixture: bomb
  it.skip('stops streaming as soon as the limit is crossed and removes partial output', () => {
    // pending: extraction is not implemented yet
  });

  // Fixture: nested-bomb
  it.skip('rejects a nested archive with NESTED_ARCHIVE when maxNestingDepth is 0', () => {
    // pending: extraction is not implemented yet
  });

  // Fixture: nested-bomb
  it.skip('shares the total size budget across nesting levels when nesting is allowed', () => {
    // pending: extraction is not implemented yet
  });
});
