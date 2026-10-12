package edge

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/snapshot"
	"github.com/Prateeks16/vexel/pkg/vexelauth"
)

const (
	sessionCookie  = "vexel_session"
	reservedPrefix = "/.vexel/"
)

type forwardKey struct{}

type forwardInfo struct {
	token string
	email string
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := s.state.Load()
	if st == nil {
		http.Error(w, "edge is starting", http.StatusServiceUnavailable)
		return
	}
	host := hostOnly(r.Host)
	a := st.apps[host]
	if a == nil {
		http.Error(w, "unknown application", http.StatusNotFound)
		return
	}
	if strings.HasPrefix(r.URL.Path, reservedPrefix) {
		s.serveReserved(w, r, st, a)
		return
	}

	raw, claims, err := s.session(r, st, a)
	if err != nil {
		s.challenge(w, r, st, a)
		return
	}

	ip := clientIP(r)
	device := s.trustedDevice(st, a, claims)
	d := a.policies.Evaluate(policy.Identity{Email: claims.Email, Groups: claims.Groups}, policy.Request{IP: ip, DeviceID: device})
	ev := audit.Event{
		Tenant: a.TenantID, App: a.ID, User: claims.Email, Device: device, Method: r.Method, Host: host, Path: r.URL.Path,
		Policy: d.Policy, Reason: d.Reason,
	}
	if ip.IsValid() {
		ev.IP = ip.String()
	}
	if !d.Allowed {
		ev.Type = audit.TypeAccessDenied
		// A session from before the app required a trusted device never went
		// through the device check: send the browser to sign in again, which
		// asks for the device. Tokens that were checked get the explanation,
		// so this can't loop.
		if a.usesDevice && device == "" && !claims.DeviceChecked && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			ev.Reason = "redirected to device check"
			s.audit.Emit(ev)
			s.challenge(w, r, st, a)
			return
		}
		s.audit.Emit(ev)
		msg := "access denied by policy"
		if a.usesDevice && device == "" {
			msg = "This application can only be used from a trusted company device.\n" +
				"Use your enrolled device, or ask your administrator to enroll this one."
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	}
	ev.Type = audit.TypeAccessAllowed
	s.audit.Emit(ev)

	ctx := context.WithValue(r.Context(), forwardKey{}, forwardInfo{token: raw, email: claims.Email})
	a.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// trustedDevice returns the token's device if it is an active device of this
// app's tenant belonging to the signed-in user, and "" otherwise. A revoked
// device stops counting at the next sync even though the token still names it.
func (s *Server) trustedDevice(st *state, a *app, claims *vexelauth.Claims) string {
	if claims.DeviceID == "" {
		return ""
	}
	d, ok := st.devices[claims.DeviceID]
	if !ok {
		s.requestSync() // possibly enrolled moments ago
		return ""
	}
	if d.TenantID != a.TenantID || !strings.EqualFold(d.Email, claims.Email) {
		return ""
	}
	return d.ID
}

func (s *Server) session(r *http.Request, st *state, a *app) (string, *vexelauth.Claims, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", nil, errNoSession
	}
	claims, err := s.verifyAppToken(r, st, a, c.Value)
	if err != nil {
		return "", nil, err
	}
	return c.Value, claims, nil
}

// verifyAppToken checks signature, audience and expiry, then the checks that
// can change after issuance: tenant ownership and offboarding.
func (s *Server) verifyAppToken(r *http.Request, st *state, a *app, raw string) (*vexelauth.Claims, error) {
	claims, err := st.verifier.Verify(r.Context(), raw, a.Hostname)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != a.TenantID {
		return nil, errWrongTenant
	}
	if st.disabled[snapshot.UserKey(claims.TenantID, claims.Email)] {
		return nil, errUserDisabled
	}
	return claims, nil
}

// challenge sends browsers to the login flow; other clients get a 401.
func (s *Server) challenge(w http.ResponseWriter, r *http.Request, st *state, a *app) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	q := url.Values{"app": {a.ID}, "rd": {scheme + "://" + r.Host + r.URL.RequestURI()}}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, st.snap.AuthURL+"/auth/login?"+q.Encode(), http.StatusFound)
}

func (s *Server) serveReserved(w http.ResponseWriter, r *http.Request, st *state, a *app) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	switch r.URL.Path {
	case "/.vexel/authorized":
		// The control plane redirects here with a freshly issued app token,
		// which becomes this app's host-only session cookie.
		raw := r.URL.Query().Get("token")
		claims, err := s.verifyAppToken(r, st, a, raw)
		if err != nil {
			s.log.Warn("rejected authorization token", "app", a.ID, "err", err)
			http.Error(w, "invalid or expired login, please try again", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    raw,
			Path:     "/",
			Expires:  claims.ExpiresAt.Time,
			MaxAge:   int(time.Until(claims.ExpiresAt.Time).Seconds()),
			HttpOnly: true,
			Secure:   s.cfg.CookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, safeRedirect(r.URL.Query().Get("rd")), http.StatusFound)

	case "/.vexel/logout":
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure})
		http.Redirect(w, r, st.snap.AuthURL+"/auth/logout", http.StatusFound)

	default:
		http.NotFound(w, r)
	}
}

// safeRedirect only allows same-origin relative paths, so the authorized
// endpoint cannot be used as an open redirect.
func safeRedirect(rd string) string {
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, reservedPrefix) {
		return "/"
	}
	return rd
}

func hostOnly(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// clientIP uses the TCP peer address. Trusting X-Forwarded-For requires an
// explicit list of trusted load balancers, which is not configurable yet.
func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
