<script setup lang="ts">
import { useTheme } from '~/composables/useTheme'

// Activate the theme as early as possible so the first paint is in
// the right palette — avoids the "white flash on dark mode" you see
// in cheap dashboards.
useTheme().mount()
</script>

<template>
  <div class="min-h-dvh bg-bg text-ink antialiased">
    <NuxtLoadingIndicator color="rgb(var(--brand))" :height="2" />
    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>
    <AppToastTray />
  </div>
</template>
