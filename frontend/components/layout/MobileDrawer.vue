<script setup lang="ts">
import { onBeforeUnmount, watch } from 'vue'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ (e: 'update:open', v: boolean): void }>()

function close() {
  emit('update:open', false)
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') close()
}

watch(
  () => props.open,
  (v) => {
    if (typeof document === 'undefined') return
    if (v) document.addEventListener('keydown', onKey)
    else document.removeEventListener('keydown', onKey)
  },
)
onBeforeUnmount(() => {
  if (typeof document !== 'undefined') document.removeEventListener('keydown', onKey)
})
</script>

<template>
  <Teleport to="body">
    <Transition
      enter-active-class="transition duration-150"
      enter-from-class="opacity-0"
      enter-to-class="opacity-100"
      leave-active-class="transition duration-100"
      leave-from-class="opacity-100"
      leave-to-class="opacity-0"
    >
      <div v-if="open" class="fixed inset-0 z-30 md:hidden bg-black/40 backdrop-blur-sm" @click="close" />
    </Transition>
    <Transition
      enter-active-class="transition duration-200 ease-out"
      enter-from-class="-translate-x-full"
      enter-to-class="translate-x-0"
      leave-active-class="transition duration-150 ease-in"
      leave-from-class="translate-x-0"
      leave-to-class="-translate-x-full"
    >
      <aside
        v-if="open"
        class="fixed inset-y-0 left-0 z-40 md:hidden flex w-72 max-w-[85vw] flex-col border-r border-line bg-surface shadow-soft"
      >
        <Sidebar :on-navigate="close" />
      </aside>
    </Transition>
  </Teleport>
</template>
