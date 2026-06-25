import { defineConfig } from 'vitest/config'

// Unit tests for the pure TS modules (formatting, ATT&CK mapping, token store,
// API client). Component/runtime tests against a live `sigil run` are e2e work.
export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.test.ts'],
  },
})
