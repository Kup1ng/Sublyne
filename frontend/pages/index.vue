<script setup lang="ts">
// Landing page just bounces to the dashboard. The auth middleware will
// re-route to /login if the session is missing.
definePageMeta({ layout: false })
const router = useRouter()
router.replace('/dashboard')
</script>

<template>
  <div />
</template>
