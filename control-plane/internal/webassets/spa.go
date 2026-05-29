// Package webassets implements the HTTP handler that serves the Nuxt 3
// single-page application out of an embedded (or on-disk) file system.
//
// Two concerns live here:
//
//  1. Path obfuscation. The panel is mounted under a random
//     `/<web_path>/` chosen at install time. Nuxt cannot bake that
//     prefix into its build, so the build instead writes a placeholder
//     sentinel (`/__SUBLYNE_WEB_PATH__/`) anywhere `app.baseURL`
//     would appear, and this handler rewrites that sentinel to the
//     real prefix for every text-content response.
//
//  2. SPA routing. A Vue Router route like `/<web_path>/settings`
//     must serve `index.html` so the client-side router can resolve
//     it. Any request that doesn't match a file in the dist falls
//     back to index.html.
package webassets

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// PlaceholderWebPath is the sentinel baked into the SPA build by
// `pnpm build`. Setting NUXT_APP_BASE_URL to this value causes Nuxt
// to emit it everywhere `app.baseURL` would otherwise live —
// `index.html` references, the Vite manifest baked into the entry
// chunk, lazy-loaded chunks, CSS `url(...)` references, and so on.
//
// The handler rewrites every occurrence of this string to "/<webPath>/"
// before sending text responses, so the SPA loads its assets and
// fetches the API from under the obfuscated prefix.
const PlaceholderWebPath = "/__SUBLYNE_WEB_PATH__/"

// MetaTagName is the name attribute the handler injects into
// `index.html` so the SPA's `useApi` composable can discover the
// runtime web prefix without round-tripping the server.
const MetaTagName = "sublyne-web-path"

// emptyFaviconLink stops the browser from auto-requesting
// `/favicon.ico` (which is *outside* the obfuscated prefix and would
// always 404). The data URL trick is the standard cure — see the
// W3C `<link rel="icon">` spec.
const emptyFaviconLink = `<link rel="icon" href="data:,">`

// SPAHandler builds an http.Handler that serves the SPA from fsys.
// webPath is the obfuscated prefix without surrounding slashes (e.g.
// "x7Kp9aR2"); the handler computes the full replacement
// ("/x7Kp9aR2/") and the meta-tag content ("/x7Kp9aR2") itself.
//
// The handler expects to receive requests with the prefix already
// stripped by the parent router — `r.URL.Path` should be the relative
// path inside the dist (e.g. "/", "/_nuxt/entry.abc.js",
// "/dashboard").
//
// fsys may be nil; in that case the handler responds 503 with a
// short text message so operators running dev builds without
// `pnpm build` get a useful error rather than a confusing 500.
func SPAHandler(fsys fs.FS, webPath string) http.Handler {
	if fsys == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "panel UI is not built; run `pnpm build` in frontend/ or build with -tags=embed", http.StatusServiceUnavailable)
		})
	}
	replacement := []byte("/" + webPath + "/")
	headInject := []byte(`<meta name="` + MetaTagName + `" content="/` + webPath + `">` + emptyFaviconLink)
	placeholder := []byte(PlaceholderWebPath)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlPath := strings.TrimPrefix(r.URL.Path, "/")
		if urlPath == "" {
			urlPath = "index.html"
		}

		content, ctype, err := readAsset(fsys, urlPath)
		if errors.Is(err, fs.ErrNotExist) {
			// SPA fallback: any unmatched path under the prefix
			// renders index.html so Vue Router can take it from there.
			content, ctype, err = readAsset(fsys, "index.html")
		}
		if err != nil {
			http.Error(w, "panel asset unavailable", http.StatusInternalServerError)
			return
		}

		if isTextual(ctype) {
			content = bytes.ReplaceAll(content, placeholder, replacement)
		}
		if strings.HasPrefix(ctype, "text/html") {
			content = injectMeta(content, headInject)
		}

		w.Header().Set("Content-Type", ctype)
		// The panel UI is loaded over plain HTTP per PRD §4.1. Disable
		// the browser cache so a panel update via setup.sh's Update
		// option is picked up on the very next page load rather than
		// after a hard refresh.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(content)
	})
}

func readAsset(fsys fs.FS, name string) ([]byte, string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if stat.IsDir() {
		// Treat directory hits as "not found" so the SPA fallback
		// runs. Without this, fs.Sub on a bare directory request
		// would return the directory listing.
		return nil, "", fs.ErrNotExist
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, "", err
	}
	return buf, contentTypeFor(name), nil
}

func contentTypeFor(name string) string {
	ext := strings.ToLower(path.Ext(name))
	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json", ".map":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".otf":
		return "font/otf"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".xml":
		return "application/xml; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func isTextual(ctype string) bool {
	switch {
	case strings.HasPrefix(ctype, "text/"):
		return true
	case strings.HasPrefix(ctype, "application/javascript"):
		return true
	case strings.HasPrefix(ctype, "application/json"):
		return true
	case strings.HasPrefix(ctype, "application/xml"):
		return true
	case strings.HasPrefix(ctype, "image/svg+xml"):
		return true
	default:
		return false
	}
}

// injectMeta inserts the meta tag immediately after the opening
// `<head>` so the SPA can read it before its own scripts execute. If
// the document doesn't contain a `<head>` (shouldn't happen for a
// Nuxt build, but defensive coding is cheap), the original content
// is returned unchanged.
func injectMeta(html, meta []byte) []byte {
	idx := bytes.Index(html, []byte("<head>"))
	if idx < 0 {
		return html
	}
	out := make([]byte, 0, len(html)+len(meta))
	out = append(out, html[:idx+len("<head>")]...)
	out = append(out, meta...)
	out = append(out, html[idx+len("<head>"):]...)
	return out
}
