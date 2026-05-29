// Route guard. Every navigation refreshes the session against the
// server once, then redirects unauthenticated users to /login (except
// when they're already there) and authed users away from /login.

export default defineNuxtRouteMiddleware(async (to) => {
  const auth = useAuth()
  if (!auth.ready.value) {
    await auth.refresh().catch(() => {
      /* swallow — refresh sets ready=true in finally */
    })
  }

  const isLogin = to.path === '/login'
  if (!auth.isAuthed.value && !isLogin) {
    return navigateTo({ path: '/login', query: { next: to.fullPath } })
  }
  if (auth.isAuthed.value && isLogin) {
    return navigateTo('/dashboard')
  }
})
