import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  // shortcut: tsup 8 injects the baseUrl option that TypeScript 6 deprecates; drop this on a tsup release that stops doing so.
  dts: { compilerOptions: { ignoreDeprecations: '6.0' } },
  clean: true,
  target: 'node20',
  platform: 'node',
  sourcemap: true,
});
