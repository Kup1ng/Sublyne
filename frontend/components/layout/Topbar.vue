<script setup lang="ts">
import { Menu } from 'lucide-vue-next'

defineProps<{ title?: string; subtitle?: string }>()
const emit = defineEmits<{ (e: 'openMenu'): void }>()
</script>

<template>
  <header
    class="sticky top-0 z-20 -mx-6 mb-8 border-b border-line/80 bg-bg/90 px-6 py-6 backdrop-blur-md md:-mx-10 md:px-10"
  >
    <div class="flex items-start justify-between gap-4">
      <div class="flex min-w-0 items-start gap-3">
        <button
          type="button"
          class="md:hidden mt-0.5 inline-flex size-9 items-center justify-center rounded-xl border border-line text-subtle hover:text-ink hover:bg-elevated"
          @click="emit('openMenu')"
          aria-label="Open menu"
        >
          <Menu class="size-4" />
        </button>
        <div class="min-w-0">
          <h1
            v-if="title"
            class="truncate text-[22px] font-semibold leading-tight tracking-[-0.018em] text-ink"
          >
            {{ title }}
          </h1>
          <p v-if="subtitle" class="mt-1 truncate text-[13px] text-subtle">{{ subtitle }}</p>
        </div>
      </div>
      <div class="flex shrink-0 items-center gap-2">
        <slot name="actions" />
      </div>
    </div>
  </header>
</template>
