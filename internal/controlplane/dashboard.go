package controlplane

import (
	"io/fs"
	"net/http"
	"path"

	"github.com/Prateeks16/vexel/web"
)

// dashboardCSP allows only same-origin scripts, styles and API calls. The
// dashboard never uses inline script or third-party resources, so an
// injected <script> or exfiltration via an external URL is blocked outright.
const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Set explicitly: on Windows the OS registry can map .js to text/plain,
// which browsers refuse to run as a module under nosniff.
var dashboardTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".svg":  "image/svg+xml",
}

func (s *Server) routeDashboard() error {
	assets, err := fs.Sub(web.Dashboard, "dashboard")
	if err != nil {
		return err
	}
	files := http.StripPrefix("/admin", http.FileServerFS(assets))

	s.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dashboardPath, http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /admin/login", s.handleAdminLogin)
	s.mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dashboardPath+"assets/favicon.svg", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", dashboardCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-cache")
		ext := path.Ext(r.URL.Path)
		if r.URL.Path == dashboardPath {
			ext = ".html"
		}
		if ct, ok := dashboardTypes[ext]; ok {
			h.Set("Content-Type", ct)
		}
		files.ServeHTTP(w, r)
	})
	return nil
}
