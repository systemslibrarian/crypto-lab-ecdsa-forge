import { defineConfig } from 'vitest/config';

/**
 * Unit-test config for the crypto core. Runs the reference-vector and
 * property tests in `test/`. The Playwright accessibility suite in `e2e/`
 * is deliberately excluded — it is driven by `npm run test:a11y`.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
