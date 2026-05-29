// Post-build: ensure the placeholder web path is present in the built
// HTML / JS so the Go server can substitute every occurrence with the
// operator's actual /<webpath>/ at serve time. Also inject the
// <meta name="sublyne-web-path"> tag the Go SPA handler updates per
// request, and assert the build didn't accidentally inline an
// absolute path that would break the substitution.

import { readFile, writeFile, readdir } from 'node:fs/promises'
import { resolve, join } from 'node:path'

const PLACEHOLDER = '/__SUBLYNE_WEB_PATH__/'
const META_TAG = '<meta name="sublyne-web-path" content="__SUBLYNE_WEB_PATH__">'

const dist = resolve(process.cwd(), '.output', 'public')
const indexPath = join(dist, 'index.html')

async function* walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  for (const e of entries) {
    const p = join(dir, e.name)
    if (e.isDirectory()) yield* walk(p)
    else yield p
  }
}

async function patchIndex() {
  let html = await readFile(indexPath, 'utf8')

  if (!html.includes(PLACEHOLDER)) {
    console.error(
      `build-spa-index: placeholder ${PLACEHOLDER} not found in index.html. ` +
        'Did NUXT_APP_BASE_URL get overridden during build? ' +
        'Without it the Go server cannot rewrite the prefix.',
    )
    process.exit(1)
  }

  if (!html.includes('name="sublyne-web-path"')) {
    html = html.replace('<head>', `<head>\n    ${META_TAG}`)
    await writeFile(indexPath, html, 'utf8')
    console.log('build-spa-index: injected <meta name="sublyne-web-path"> into index.html')
  } else {
    console.log('build-spa-index: meta tag already present, leaving index.html untouched')
  }
}

async function assertNoLeakedAbsolutePaths() {
  // Walk every built asset; ensure we never emit a hardcoded
  // /__SOMETHING__ that isn't our intended placeholder. A missed
  // substitution would otherwise silently shadow real API calls.
  const allowed = new Set([PLACEHOLDER])
  for await (const file of walk(dist)) {
    if (!/\.(html|js|css|mjs|json)$/i.test(file)) continue
    const text = await readFile(file, 'utf8').catch(() => '')
    const matches = text.match(/\/__[A-Z0-9_]+__\//g)
    if (!matches) continue
    for (const m of matches) {
      if (!allowed.has(m)) {
        console.error(`build-spa-index: unexpected placeholder ${m} found in ${file}`)
        process.exit(1)
      }
    }
  }
}

await patchIndex()
await assertNoLeakedAbsolutePaths()
console.log('build-spa-index: ok')
