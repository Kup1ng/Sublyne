import type { Config } from 'tailwindcss'

// Sublyne is intentionally a small, opinionated palette. We map a few
// semantic tokens to CSS custom properties that flip between light and
// dark via `class="dark"` on <html>. Everything else stays raw Tailwind.
export default {
  darkMode: 'class',
  content: [
    './app.vue',
    './components/**/*.{vue,ts}',
    './composables/**/*.{vue,ts}',
    './layouts/**/*.vue',
    './middleware/**/*.ts',
    './pages/**/*.vue',
    './plugins/**/*.ts',
  ],
  theme: {
    extend: {
      colors: {
        // Semantic tokens (driven by CSS custom properties in main.css)
        bg: 'rgb(var(--bg) / <alpha-value>)',
        surface: 'rgb(var(--surface) / <alpha-value>)',
        elevated: 'rgb(var(--elevated) / <alpha-value>)',
        muted: 'rgb(var(--muted) / <alpha-value>)',
        line: 'rgb(var(--line) / <alpha-value>)',
        ink: 'rgb(var(--ink) / <alpha-value>)',
        subtle: 'rgb(var(--subtle) / <alpha-value>)',
        faint: 'rgb(var(--faint) / <alpha-value>)',
        brand: {
          DEFAULT: 'rgb(var(--brand) / <alpha-value>)',
          strong: 'rgb(var(--brand-strong) / <alpha-value>)',
          soft: 'rgb(var(--brand-soft) / <alpha-value>)',
          edge: 'rgb(var(--brand-edge) / <alpha-value>)',
        },
        accent: 'rgb(var(--accent) / <alpha-value>)',
        ok: 'rgb(var(--ok) / <alpha-value>)',
        warn: 'rgb(var(--warn) / <alpha-value>)',
        danger: 'rgb(var(--danger) / <alpha-value>)',
      },
      fontFamily: {
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          'sans-serif',
        ],
        mono: [
          'JetBrains Mono',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          'monospace',
        ],
      },
      borderRadius: {
        xl: '0.875rem',
        '2xl': '1.125rem',
      },
      boxShadow: {
        soft: '0 1px 2px rgb(0 0 0 / 0.04), 0 4px 16px -8px rgb(0 0 0 / 0.10)',
        glow: '0 0 0 1px rgb(var(--brand) / 0.35), 0 12px 48px -16px rgb(var(--brand) / 0.55)',
      },
      keyframes: {
        pulseSoft: {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.55', transform: 'scale(1.18)' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(2px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        sheen: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
      },
      animation: {
        pulseSoft: 'pulseSoft 2.4s ease-in-out infinite',
        fadeIn: 'fadeIn 160ms ease-out both',
        sheen: 'sheen 8s ease-in-out infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
