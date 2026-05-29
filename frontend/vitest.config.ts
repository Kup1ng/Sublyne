import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      // Nuxt's `~/` and `@/` aliases both resolve to the project root
      // at build time. Vitest runs outside Nuxt so we replicate the
      // mapping here; without it, `import '~/utils/format'` fails.
      '~': fileURLToPath(new URL('.', import.meta.url)),
      '@': fileURLToPath(new URL('.', import.meta.url)),
    },
  },
  test: {
    environment: 'happy-dom',
    include: ['tests/**/*.test.ts'],
    globals: false,
  },
})
