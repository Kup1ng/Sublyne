<script setup lang="ts">
// The tunnel create form is now a modal on the /tunnels listing
// (v3.1.0). This route is kept only as a thin redirect so existing
// links and bookmarks to /tunnels/new keep working: it bounces to the
// listing and signals it (via ?new=1) to auto-open the create modal.
definePageMeta({
  middleware() {
    return navigateTo({ path: '/tunnels', query: { new: '1' } }, { replace: true })
  },
})
</script>

<template>
  <div />
</template>
