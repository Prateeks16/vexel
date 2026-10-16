package controlplane

import (
	"context"
	"crypto/rand"
	"errors"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/snapshot"
	"github.com/Prateeks16/vexel/internal/store"
	"github.com/Prateeks16/vexel/pkg/vexelauth"
)

const (
	cpSessionCookie = "vexel_cp_session"
	cpAudience      = "vexel:controlplane"
	dashboardPath   = "/admin/"
)

type identity struct {
	TenantID string
	Email    string
	Groups   []string
	Method   string
	DeviceID string // trusted device proven during this session, if any
}

// loginTarget is where the user is headed after login: one of the tenant's
// apps, or (app == nil) the tenant's admin dashboard.
type loginTarget struct {
	tenantID   string
	tenantSlug string        // dashboard logins only
	app        *snapshot.App // nil for the dashboard
	rd         *url.URL      // full URL on the app's hostname; apps only
}

// hidden returns the form fields that identify this target.
func (t *loginTarget) hidden() map[string]string {
	if t.app == nil {
		return map[string]string{"tenant": t.tenantSlug}
	}
	return map[string]string{"app": t.app.ID, "rd": t.rd.String()}
}

func (t *loginTarget) auditApp() string {
	if t.app == nil {
		return "dashboard"
	}
	return t.app.ID
}

type badRequest string

func (e badRequest) Error() string { return string(e) }

// appTarget resolves and checks an app login target. It only accepts
// redirects back to the app's own hostname, so the login endpoint cannot hand
// tokens to arbitrary sites.
func (s *Server) appTarget(r *http.Request, appID, rd string) (*loginTarget, error) {
	b, err := s.currentSnapshot(r.Context())
	if err != nil {
		return nil, err
	}
	app := b.apps[appID]
	if app == nil {
		return nil, badRequest("unknown application")
	}
	u, err := url.Parse(rd)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, badRequest("invalid redirect")
	}
	if !strings.EqualFold(u.Hostname(), app.Hostname) {
		return nil, badRequest("redirect does not match application")
	}
	if !s.cfg.DevMode && u.Scheme != "https" {
		return nil, badRequest("redirect must use https")
	}
	return &loginTarget{tenantID: app.TenantID, app: app, rd: u}, nil
}

func (s *Server) dashboardTarget(ctx context.Context, slug string) (*loginTarget, error) {
	if !slugRE.MatchString(slug) {
		return nil, badRequest("unknown organisation")
	}
	t, err := s.store.GetTenantBySlug(ctx, slug)
	if errors.Is(err, store.ErrNotFound) {
		return nil, badRequest("unknown organisation")
	}
	if err != nil {
		return nil, err
	}
	return &loginTarget{tenantID: t.ID, tenantSlug: t.Slug}, nil
}

func (s *Server) loginError(w http.ResponseWriter, err error) {
	var br badRequest
	if errors.As(err, &br) {
		http.Error(w, string(br), http.StatusBadRequest)
		return
	}
	s.log.Error("login", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	t, err := s.appTarget(r, q.Get("app"), q.Get("rd"))
	if err != nil {
		s.loginError(w, err)
		return
	}
	s.beginLogin(w, r, t)
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	t, err := s.dashboardTarget(r.Context(), r.URL.Query().Get("tenant"))
	if err != nil {
		s.loginError(w, err)
		return
	}
	s.beginLogin(w, r, t)
}

// beginLogin reuses an existing session for the same tenant (single sign-on)
// or starts the tenant's login method. Sessions never cross tenants: each
// tenant trusts only its own identity provider.
func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request, t *loginTarget) {
	b, err := s.currentSnapshot(r.Context())
	if err != nil {
		s.loginError(w, err)
		return
	}
	if id, ok := s.currentSession(r); ok && id.TenantID == t.tenantID && !b.disabled[snapshot.UserKey(id.TenantID, id.Email)] {
		s.completeLogin(w, r, t, id)
		return
	}

	idp, err := s.store.GetIdentityProvider(r.Context(), t.tenantID)
	switch {
	case err == nil:
		s.startOIDC(w, r, t, idp)
	case errors.Is(err, store.ErrNotFound) && s.cfg.Auth.DevLogin:
		name := "the admin dashboard"
		if t.app != nil {
			name = t.app.Name
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		devLoginPage.Execute(w, map[string]any{"Name": name, "Hidden": t.hidden()})
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "this organisation has not configured an identity provider", http.StatusServiceUnavailable)
	default:
		s.loginError(w, err)
	}
}

func (s *Server) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Auth.DevLogin {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	var t *loginTarget
	var err error
	if appID := r.PostForm.Get("app"); appID != "" {
		t, err = s.appTarget(r, appID, r.PostForm.Get("rd"))
	} else {
		t, err = s.dashboardTarget(r.Context(), r.PostForm.Get("tenant"))
	}
	if err != nil {
		s.loginError(w, err)
		return
	}
	// A tenant with a real identity provider can't be entered via dev login.
	if _, err := s.store.GetIdentityProvider(r.Context(), t.tenantID); !errors.Is(err, store.ErrNotFound) {
		http.Error(w, "dev login is not available for this organisation", http.StatusForbidden)
		return
	}
	email, err := normalizeEmail(r.PostForm.Get("email"))
	if err != nil {
		http.Error(w, "a valid email is required", http.StatusBadRequest)
		return
	}
	var groups []string
	for _, g := range strings.Split(r.PostForm.Get("groups"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	s.finishAuthentication(w, r, t, identity{TenantID: t.tenantID, Email: email, Groups: groups, Method: "dev"})
}

// finishAuthentication runs once the user has proven who they are.
func (s *Server) finishAuthentication(w http.ResponseWriter, r *http.Request, t *loginTarget, id identity) {
	user, err := s.store.RecordLogin(r.Context(), id.TenantID, id.Email, id.Groups, time.Now())
	if err != nil {
		s.loginError(w, err)
		return
	}
	if user.DisabledAt != nil {
		s.audit.Emit(audit.Event{Type: audit.TypeLoginDenied, Tenant: id.TenantID, User: id.Email, App: t.auditApp(), IP: remoteIP(r), Reason: "user disabled"})
		http.Error(w, "your account has been disabled", http.StatusForbidden)
		return
	}
	if err := s.setSession(w, id); err != nil {
		s.loginError(w, err)
		return
	}
	s.audit.Emit(audit.Event{Type: audit.TypeLogin, Tenant: id.TenantID, User: id.Email, App: t.auditApp(), IP: remoteIP(r), Reason: id.Method})
	s.completeLogin(w, r, t, id)
}

// completeLogin sends dashboard logins to the dashboard, and for apps issues
// an app-scoped token and hands it to the edge.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, t *loginTarget, id identity) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if t.app == nil {
		http.Redirect(w, r, dashboardPath, http.StatusFound)
		return
	}
	id, ok := s.deviceStep(w, r, t, id)
	if !ok {
		return
	}

	now := time.Now()
	tok, err := s.signer.Sign(vexelauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.PublicURL,
			Subject:   id.Email,
			Audience:  jwt.ClaimStrings{t.app.Hostname},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.app.SessionDuration)),
			ID:        rand.Text(),
		},
		TenantID: id.TenantID,
		Email:    id.Email,
		Groups:   id.Groups,
		DeviceID: id.DeviceID,

		DeviceChecked: policy.UsesDevice(t.app.Policies),
	})
	if err != nil {
		s.loginError(w, err)
		return
	}
	dest := url.URL{
		Scheme:   t.rd.Scheme,
		Host:     t.rd.Host,
		Path:     "/.vexel/authorized",
		RawQuery: url.Values{"token": {tok}, "rd": {t.rd.RequestURI()}}.Encode(),
	}
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// sessionClaims is the control plane's own session. CSRF is a per-session
// secret the dashboard must echo in a header on every state-changing call.
type sessionClaims struct {
	vexelauth.Claims
	CSRF string `json:"csrf"`
}

func (s *Server) setSession(w http.ResponseWriter, id identity) error {
	now := time.Now()
	exp := now.Add(s.cfg.SessionDuration)
	tok, err := s.signer.Sign(sessionClaims{
		Claims: vexelauth.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    s.cfg.PublicURL,
				Subject:   id.Email,
				Audience:  jwt.ClaimStrings{cpAudience},
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(exp),
				ID:        rand.Text(),
			},
			TenantID: id.TenantID,
			Email:    id.Email,
			Groups:   id.Groups,
			DeviceID: id.DeviceID,
		},
		CSRF: rand.Text(),
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cpSessionCookie,
		Value:    tok,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return s.signer.Key(ctx, kid)
	}
}

func (s *Server) parseSession(r *http.Request) (*sessionClaims, bool) {
	c, err := r.Cookie(cpSessionCookie)
	if err != nil {
		return nil, false
	}
	sc := &sessionClaims{}
	_, err = jwt.ParseWithClaims(c.Value, sc, s.keyfunc(r.Context()),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(s.cfg.PublicURL),
		jwt.WithAudience(cpAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil || sc.TenantID == "" || sc.Email == "" {
		return nil, false
	}
	return sc, true
}

func (s *Server) currentSession(r *http.Request) (identity, bool) {
	sc, ok := s.parseSession(r)
	if !ok {
		return identity{}, false
	}
	return identity{TenantID: sc.TenantID, Email: sc.Email, Groups: sc.Groups, DeviceID: sc.DeviceID}, true
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.currentSession(r); ok {
		s.audit.Emit(audit.Event{Type: audit.TypeLogout, Tenant: id.TenantID, User: id.Email, IP: remoteIP(r)})
	}
	http.SetCookie(w, &http.Cookie{Name: cpSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("You have been signed out.\n"))
}

var devLoginPage = template.Must(template.New("dev-login").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Vexel dev login</title>
<style>
body{font-family:system-ui,sans-serif;background:#f6f6f4;color:#1d1d1b;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.08);width:min(360px,calc(100vw - 32px))}
label{display:block;margin:.75rem 0 .25rem;font-size:.9rem}input{width:100%;box-sizing:border-box;padding:.5rem;font:inherit}
button{margin-top:1.25rem;width:100%;padding:.6rem;font:inherit;cursor:pointer}.warn{font-size:.8rem;color:#9a3412}
</style></head>
<body><form method="post" action="/auth/dev-login">
<h1 style="font-size:1.2rem;margin:0">Sign in to {{.Name}}</h1>
<p class="warn">Development login: no password is checked. Never enable this in production.</p>
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<label for="email">Email</label><input id="email" name="email" type="email" required autofocus>
<label for="groups">Groups (comma separated)</label><input id="groups" name="groups">
<button type="submit">Continue</button>
</form></body></html>`))

// remoteIP is the TCP peer address without its port, matching how edges
// record client IPs in the access log.
func remoteIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return r.RemoteAddr
}
