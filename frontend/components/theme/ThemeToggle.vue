<script setup lang="ts">
import { Moon, Sun } from 'lucide-vue-next'
import { useTheme } from '~/composables/useTheme'
const { mode, toggle } = useTheme()
</script>

<template>
  <button
    type="button"
    @click="toggle"
    :title="mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'"
    aria-label="Toggle theme"
    class="inline-flex size-9 items-center justify-center rounded-xl border border-line bg-surface text-subtle transition hover:text-ink hover:bg-elevated"
  >
    <Moon v-if="mode === 'dark'" class="size-4" />
    <Sun v-else class="size-4" />
  </button>
</template>
