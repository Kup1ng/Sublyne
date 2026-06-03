<script setup lang="ts">
// The tunnel edit form is now a modal on the /tunnels listing (v3.1.0).
// This route is kept only as a thin redirect so existing links, tunnel
// cards' edit buttons, and bookmarks to /tunnels/:id keep working: it
// bounces to the listing and signals it (via ?edit=:id) to auto-open
// the edit modal for that tunnel.
definePageMeta({
  middleware(to) {
    return navigateTo(
      { path: '/tunnels', query: { edit: String(to.params.id) } },
      { replace: true },
    )
  },
})
</script>

<template>
  <div />
</template>
