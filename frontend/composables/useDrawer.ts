// Cross-component state for the mobile sidebar drawer. Topbar's menu
// button toggles it; MobileDrawer reads it. Keeps both ignorant of
// each other's location in the tree.

export function useDrawer() {
  const open = useState<boolean>('sublyne-drawer-open', () => false)
  function toggle() {
    open.value = !open.value
  }
  function close() {
    open.value = false
  }
  function show() {
    open.value = true
  }
  return { open, toggle, close, show }
}
