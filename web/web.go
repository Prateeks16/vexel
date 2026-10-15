// Package web holds the admin dashboard, a dependency-free single-page app
// served by the control plane at /admin/. It talks to the same /api/v1
// endpoints as API-token automation, authenticated by the session cookie.
package web

import "embed"

//go:embed dashboard
var Dashboard embed.FS
