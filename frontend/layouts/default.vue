<script setup lang="ts">
import { useDrawer } from '~/composables/useDrawer'
const drawer = useDrawer()
</script>

<template>
  <div class="flex min-h-dvh">
    <aside
      class="sticky top-0 hidden h-dvh w-[260px] shrink-0 border-r border-line/80 md:flex md:flex-col"
    >
      <Sidebar />
    </aside>

    <MobileDrawer v-model:open="drawer.open.value" />

    <main class="flex min-h-dvh min-w-0 flex-1 flex-col px-6 pb-10 md:px-10">
      <slot />
    </main>
  </div>
</template>
