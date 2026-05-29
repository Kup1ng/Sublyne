// Sublyne Nuxt config — SPA mode, no SSR. The Go control plane serves
// the built `.output/public` tree under its obfuscated `/<web_path>/`
// prefix, so we set `app.baseURL` to a placeholder the post-build
// script (scripts/build-spa-index.mjs) keeps intact for the Go server
// to substitute at serve time.

import { defineNuxtConfig } from 'nuxt/config'

const placeholder = process.env.NUXT_APP_BASE_URL || '/__SUBLYNE_WEB_PATH__/'

export default defineNuxtConfig({
  ssr: false,
  devtools: { enabled: false },
  compatibilityDate: '2025-01-15',

  app: {
    baseURL: placeholder,
    head: {
      htmlAttrs: { lang: 'en' },
      title: 'Sublyne',
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'theme-color', content: '#09090b' },
        // The Go server substitutes <meta name="sublyne-web-path">
        // into the served index.html at request time. In dev the meta
        // tag is absent and the API client falls back to an empty
        // prefix; Vite's proxy then routes /api/* to the dev panel.
      ],
      script: [
        {
          // Set the theme class on <html> BEFORE the first paint so
          // there's no white-flash before useTheme().mount() runs. The
          // logic: explicit 'light' in localStorage = leave the class
          // off, everything else (including no stored value) = dark.
          innerHTML:
            "(function(){try{var v=localStorage.getItem('sublyne.theme');if(v!=='light'){document.documentElement.classList.add('dark');document.documentElement.style.colorScheme='dark'}}catch(e){}})();",
          tagPosition: 'head',
        },
      ],
    },
  },

  modules: ['@nuxtjs/tailwindcss'],

  // Auto-import every component under components/ WITHOUT path
  // prefixes — by default Nuxt 3 names nested components by their
  // folder path (e.g. components/ui/AppButton.vue becomes
  // <UiAppButton/>). Sublyne intentionally writes <AppButton/> in
  // templates regardless of where the SFC lives, so flatten the
  // registration. Without this every <AppCard>, <AppInput>, etc.
  // ends up as a raw unknown HTML tag at runtime.
  components: [{ path: '~/components', pathPrefix: false }],

  css: ['~/assets/css/main.css'],

  tailwindcss: {
    cssPath: '~/assets/css/main.css',
    configPath: '~/tailwind.config',
    viewer: false,
  },

  nitro: {
    preset: 'static',
  },

  vite: {
    server: {
      proxy: {
        '/api': {
          target: process.env.NUXT_DEV_API_URL || 'http://localhost:18080',
          changeOrigin: true,
        },
      },
    },
  },

  routeRules: {
    '/_nuxt/**': { headers: { 'cache-control': 'public, max-age=31536000, immutable' } },
  },

  typescript: {
    strict: true,
    shim: false,
  },
})
