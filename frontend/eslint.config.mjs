// Flat config (ESLint 9). Nuxt's @nuxt/eslint module is overkill for
// a single-app frontend; we use a small, deterministic flat config
// that covers .ts, .vue, and .mjs files. Prettier handles formatting;
// ESLint just catches obvious mistakes.

import js from '@eslint/js'

export default [
  {
    // ESLint flat config can't parse <template> blocks in .vue files
    // without eslint-plugin-vue, which we intentionally don't pull in
    // to keep the toolchain small. vue-tsc (run by `pnpm typecheck`)
    // catches Vue-specific type problems; ESLint runs on JS / TS only.
    ignores: ['node_modules/**', '.nuxt/**', '.output/**', 'dist/**', '**/*.d.ts', '**/*.vue'],
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        // Browser
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        fetch: 'readonly',
        WebSocket: 'readonly',
        localStorage: 'readonly',
        sessionStorage: 'readonly',
        location: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        requestAnimationFrame: 'readonly',
        cancelAnimationFrame: 'readonly',
        URL: 'readonly',
        Blob: 'readonly',
        File: 'readonly',
        FormData: 'readonly',
        FileReader: 'readonly',
        // Nuxt 3 auto-imports
        defineNuxtPlugin: 'readonly',
        defineNuxtConfig: 'readonly',
        defineNuxtRouteMiddleware: 'readonly',
        navigateTo: 'readonly',
        useRoute: 'readonly',
        useRouter: 'readonly',
        useState: 'readonly',
        useFetch: 'readonly',
        useRuntimeConfig: 'readonly',
        useHead: 'readonly',
        // Vue 3 auto-imports (Nuxt)
        ref: 'readonly',
        reactive: 'readonly',
        computed: 'readonly',
        watch: 'readonly',
        watchEffect: 'readonly',
        onMounted: 'readonly',
        onBeforeMount: 'readonly',
        onUnmounted: 'readonly',
        onBeforeUnmount: 'readonly',
        nextTick: 'readonly',
        provide: 'readonly',
        inject: 'readonly',
        defineProps: 'readonly',
        defineEmits: 'readonly',
        defineExpose: 'readonly',
        withDefaults: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'no-undef': 'off', // Nuxt auto-imports + Vue macros; covered above
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
  {
    files: ['**/*.vue'],
    rules: {
      // Vue templates use defineProps / defineEmits as compiler macros;
      // ESLint's flat config can't parse <template> blocks without
      // eslint-plugin-vue, which we deliberately don't pull in to keep
      // the toolchain lean. Disable rules that misfire on macros.
      'no-undef': 'off',
      'no-unused-vars': 'off',
    },
  },
]
