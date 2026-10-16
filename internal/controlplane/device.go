package controlplane

// Device trust with hardware-bound WebAuthn credentials.
//
// An admin issues a one-time enrollment link for a user. Opened on the
// device, it registers a platform authenticator credential (Windows Hello,
// Touch ID): a key pair generated inside the TPM / Secure Enclave that cannot
// be exported. Apps whose policies use the "trusted device" rule then ask for
// an assertion from one of the user's credentials at sign-in, and the proven
// device ID rides in the session and app token, where edges check it is still
// active on every request.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/store"
)

const (
	ceremonyCookie   = "vexel_webauthn"
	ceremonyAudience = "vexel:webauthn"
	enrollmentTTL    = 24 * time.Hour
)

func newWebAuthn(cfg *Config) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Vexel",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
	})
}

// deviceUser adapts one user's devices to webauthn.User.
type deviceUser struct {
	id    []byte
	email string
	creds []webauthn.Credential
}

func (u *deviceUser) WebAuthnID() []byte                         { return u.id }
func (u *deviceUser) WebAuthnName() string                       { return u.email }
func (u *deviceUser) WebAuthnDisplayName() string                { return u.email }
func (u *deviceUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webauthnUserID is an opaque, stable handle: no email or tenant ID is
// handed to the authenticator.
func webauthnUserID(tenantID, email string) []byte {
	sum := sha256.Sum256([]byte("vexel-device-user\x00" + tenantID + "\x00" + strings.ToLower(email)))
	return sum[:]
}

func (s *Server) loadDeviceUser(r *http.Request, tenantID, email string) (*deviceUser, []store.Device, error) {
	devs, err := s.store.ListUserDevices(r.Context(), tenantID, email)
	if err != nil {
		return nil, nil, err
	}
	u := &deviceUser{id: webauthnUserID(tenantID, email), email: email}
	for _, d := range devs {
		var c webauthn.Credential
		if err := json.Unmarshal(d.Credential, &c); err != nil {
			return nil, nil, fmt.Errorf("device %s: %w", d.ID, err)
		}
		u.creds = append(u.creds, c)
	}
	return u, devs, nil
}

// ceremonyClaims carries WebAuthn session data between begin and finish in a
// signed, short-lived cookie, keeping the control plane stateless.
type ceremonyClaims struct {
	jwt.RegisteredClaims
	Kind    string               `json:"kind"` // "enroll" or "verify"
	Session webauthn.SessionData `json:"session"`
	Code    string               `json:"code,omitempty"` // enroll: code hash
	App     string               `json:"app,omitempty"`  // verify
	RD      string               `json:"rd,omitempty"`   // verify
}

func (s *Server) setCeremony(w http.ResponseWriter, c ceremonyClaims) error {
	now := time.Now()
	c.Issuer, c.Audience = s.cfg.PublicURL, jwt.ClaimStrings{ceremonyAudience}
	c.IssuedAt, c.ExpiresAt = jwt.NewNumericDate(now), jwt.NewNumericDate(now.Add(5*time.Minute))
	tok, err := s.signer.Sign(c)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Value: tok, Path: "/", MaxAge: 300,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	return nil
}

func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request, kind string) (*ceremonyClaims, error) {
	c, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return nil, badRequest("this step expired, please start again")
	}
	http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Path: "/", MaxAge: -1})
	cc := &ceremonyClaims{}
	_, err = jwt.ParseWithClaims(c.Value, cc, s.keyfunc(r.Context()),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(s.cfg.PublicURL), jwt.WithAudience(ceremonyAudience), jwt.WithExpirationRequired())
	if err != nil || cc.Kind != kind {
		return nil, badRequest("this step expired, please start again")
	}
	return cc, nil
}

// jsonSameOrigin guards the ceremony endpoints: they are called by fetch from
// our own pages, so anything else (a cross-site form post) is refused.
func (s *Server) jsonSameOrigin(r *http.Request) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return badRequest("expected JSON")
	}
	if r.Header.Get("Origin") != s.publicOrigin {
		return &apiAuthError{http.StatusForbidden, "cross-origin request refused"}
	}
	return nil
}

func (s *Server) ceremonyError(w http.ResponseWriter, err error) {
	var br badRequest
	var ae *apiAuthError
	switch {
	case errors.As(err, &br):
		writeJSONError(w, http.StatusBadRequest, string(br))
	case errors.As(err, &ae):
		writeJSONError(w, ae.status, ae.msg)
	default:
		s.log.Error("device ceremony", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
	}
}

// Enrollment

func (s *Server) enrollmentFromCode(r *http.Request, code string) (store.DeviceEnrollment, error) {
	e, err := s.store.GetDeviceEnrollmentByCode(r.Context(), secret.Hash(code), time.Now())
	if errors.Is(err, store.ErrNotFound) {
		return e, badRequest("this enrollment link is invalid, already used or expired; ask your administrator for a new one")
	}
	return e, err
}

func (s *Server) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	data := map[string]any{"Mode": "enroll", "Code": code}
	e, err := s.enrollmentFromCode(r, code)
	if err == nil {
		t, terr := s.store.GetTenant(r.Context(), e.TenantID)
		if terr != nil {
			s.loginError(w, terr)
			return
		}
		data["Email"], data["DeviceName"], data["Tenant"] = e.UserEmail, e.Name, t.Name
	} else {
		var br badRequest
		if !errors.As(err, &br) {
			s.loginError(w, err)
			return
		}
		data["Error"] = string(br)
	}
	s.renderDevicePage(w, data)
}

func (s *Server) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if err := s.jsonSameOrigin(r); err != nil {
		s.ceremonyError(w, err)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		s.ceremonyError(w, badRequest("invalid request"))
		return
	}
	e, err := s.enrollmentFromCode(r, body.Code)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	user, _, err := s.loadDeviceUser(r, e.TenantID, e.UserEmail)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(user.creds))
	for i := range user.creds {
		exclude = append(exclude, user.creds[i].Descriptor())
	}
	creation, session, err := s.webauthn.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform, // built-in TPM / Secure Enclave, not a roaming key
			ResidentKey:             protocol.ResidentKeyRequirementDiscouraged,
			UserVerification:        protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	if err := s.setCeremony(w, ceremonyClaims{Kind: "enroll", Session: *session, Code: secret.Hash(body.Code)}); err != nil {
		s.ceremonyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (s *Server) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	if err := s.jsonSameOrigin(r); err != nil {
		s.ceremonyError(w, err)
		return
	}
	cc, err := s.takeCeremony(w, r, "enroll")
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	e, err := s.store.GetDeviceEnrollmentByCode(r.Context(), cc.Code, time.Now())
	if err != nil {
		s.ceremonyError(w, badRequest("this enrollment link is no longer valid"))
		return
	}
	user, _, err := s.loadDeviceUser(r, e.TenantID, e.UserEmail)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	cred, err := s.webauthn.FinishRegistration(user, cc.Session, r)
	if err != nil {
		s.log.Warn("device enrollment rejected", "tenant", e.TenantID, "user", e.UserEmail, "err", err)
		s.ceremonyError(w, badRequest("the device could not be verified; please try again"))
		return
	}
	if !cred.Flags.UserVerified {
		s.ceremonyError(w, badRequest("the device must verify you with a PIN, fingerprint or face"))
		return
	}
	// A backup-eligible credential is a passkey that can sync to other
	// devices through a password manager, so it doesn't prove *this* device.
	if cred.Flags.BackupEligible && !s.cfg.AllowSyncedDeviceCredentials {
		s.ceremonyError(w, badRequest("that credential can sync to other devices (a passkey saved to a password manager). "+
			"Try again and choose this device's built-in option, such as Windows Hello or Touch ID"))
		return
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	d, err := s.store.CompleteDeviceEnrollment(r.Context(), cc.Code, store.Device{
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID), Credential: raw,
	}, time.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.ceremonyError(w, badRequest("this enrollment link is no longer valid"))
		return
	case errors.Is(err, store.ErrConflict):
		s.ceremonyError(w, badRequest("this device is already enrolled"))
		return
	case err != nil:
		s.ceremonyError(w, err)
		return
	}
	s.admin.record(r.Context(), d.TenantID, Actor("enrollment:"+e.ID), "device.enroll", d.Name+" ("+d.UserEmail+")")
	writeJSON(w, http.StatusOK, map[string]string{"device": d.Name, "user": d.UserEmail})
}

// Device check at sign-in

// deviceStep decides whether an app login must first prove a trusted device.
// It returns the identity with a still-valid device, or redirects to the
// device check and reports false.
func (s *Server) deviceStep(w http.ResponseWriter, r *http.Request, t *loginTarget, id identity) (identity, bool) {
	if t.app == nil || !policy.UsesDevice(t.app.Policies) {
		return id, true
	}
	if id.DeviceID != "" {
		b, err := s.currentSnapshot(r.Context())
		if err != nil {
			s.loginError(w, err)
			return id, false
		}
		if d, ok := b.devices[id.DeviceID]; ok && d.TenantID == id.TenantID && strings.EqualFold(d.Email, id.Email) {
			return id, true
		}
		id.DeviceID = "" // revoked since this session proved it
	}
	devs, err := s.store.ListUserDevices(r.Context(), id.TenantID, id.Email)
	if err != nil {
		s.loginError(w, err)
		return id, false
	}
	if len(devs) == 0 {
		// Nothing to prove with. Continue without a device; the edge applies
		// the policy and explains what is needed.
		return id, true
	}
	q := url.Values{"app": {t.app.ID}, "rd": {t.rd.String()}}
	http.Redirect(w, r, "/auth/device?"+q.Encode(), http.StatusFound)
	return id, false
}

func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	t, err := s.appTarget(r, q.Get("app"), q.Get("rd"))
	if err != nil {
		s.loginError(w, err)
		return
	}
	id, ok := s.currentSession(r)
	if !ok || id.TenantID != t.tenantID {
		// Not signed in (or to another tenant): start over at login.
		http.Redirect(w, r, "/auth/login?"+q.Encode(), http.StatusFound)
		return
	}
	s.renderDevicePage(w, map[string]any{"Mode": "verify", "App": t.app.ID, "AppName": t.app.Name, "RD": t.rd.String(), "Email": id.Email})
}

func (s *Server) handleDeviceBegin(w http.ResponseWriter, r *http.Request) {
	if err := s.jsonSameOrigin(r); err != nil {
		s.ceremonyError(w, err)
		return
	}
	var body struct {
		App string `json:"app"`
		RD  string `json:"rd"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		s.ceremonyError(w, badRequest("invalid request"))
		return
	}
	t, err := s.appTarget(r, body.App, body.RD)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	id, ok := s.currentSession(r)
	if !ok || id.TenantID != t.tenantID {
		s.ceremonyError(w, &apiAuthError{http.StatusUnauthorized, "your sign-in expired, please start again"})
		return
	}
	user, devs, err := s.loadDeviceUser(r, id.TenantID, id.Email)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	if len(devs) == 0 {
		s.ceremonyError(w, badRequest("you have no enrolled devices"))
		return
	}
	assertion, session, err := s.webauthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	if err := s.setCeremony(w, ceremonyClaims{Kind: "verify", Session: *session, App: t.app.ID, RD: t.rd.String()}); err != nil {
		s.ceremonyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Server) handleDeviceFinish(w http.ResponseWriter, r *http.Request) {
	if err := s.jsonSameOrigin(r); err != nil {
		s.ceremonyError(w, err)
		return
	}
	cc, err := s.takeCeremony(w, r, "verify")
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	t, err := s.appTarget(r, cc.App, cc.RD)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	id, ok := s.currentSession(r)
	if !ok || id.TenantID != t.tenantID {
		s.ceremonyError(w, &apiAuthError{http.StatusUnauthorized, "your sign-in expired, please start again"})
		return
	}
	user, devs, err := s.loadDeviceUser(r, id.TenantID, id.Email)
	if err != nil {
		s.ceremonyError(w, err)
		return
	}
	cred, err := s.webauthn.FinishLogin(user, cc.Session, r)
	if err != nil {
		s.log.Warn("device check failed", "tenant", id.TenantID, "user", id.Email, "err", err)
		s.audit.Emit(audit.Event{Type: audit.TypeLoginDenied, Tenant: id.TenantID, User: id.Email, App: t.app.ID, IP: remoteIP(r), Reason: "device check failed"})
		s.ceremonyError(w, badRequest("this device could not be verified"))
		return
	}
	if cred.Authenticator.CloneWarning {
		s.audit.Emit(audit.Event{Type: audit.TypeLoginDenied, Tenant: id.TenantID, User: id.Email, App: t.app.ID, IP: remoteIP(r), Reason: "possible cloned device credential"})
		s.ceremonyError(w, badRequest("this device's credential looks cloned; contact your administrator"))
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	var dev *store.Device
	for i := range devs {
		if devs[i].CredentialID == credID {
			dev = &devs[i]
		}
	}
	if dev == nil {
		s.ceremonyError(w, badRequest("this device could not be verified"))
		return
	}
	if raw, err := json.Marshal(cred); err == nil {
		if err := s.store.RecordDeviceUse(r.Context(), dev.TenantID, dev.ID, raw, time.Now()); err != nil {
			s.log.Error("record device use", "device", dev.ID, "err", err)
		}
	}

	id.DeviceID = dev.ID
	if err := s.setSession(w, id); err != nil {
		s.ceremonyError(w, err)
		return
	}
	s.audit.Emit(audit.Event{Type: audit.TypeDeviceVerified, Tenant: id.TenantID, User: id.Email, Device: dev.ID, App: t.app.ID, IP: remoteIP(r), Reason: dev.Name})
	next := "/auth/login?" + url.Values{"app": {t.app.ID}, "rd": {t.rd.String()}}.Encode()
	writeJSON(w, http.StatusOK, map[string]string{"next": next})
}

func (s *Server) renderDevicePage(w http.ResponseWriter, data map[string]any) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", dashboardCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	if err := devicePage.Execute(w, data); err != nil {
		s.log.Error("render device page", "err", err)
	}
}

var devicePage = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if eq .Mode "enroll"}}Enroll device{{else}}Confirm your device{{end}} · Vexel</title>
<link rel="icon" href="/admin/assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/admin/assets/app.css">
<script type="module" src="/admin/assets/device.js"></script>
</head>
<body>
<div class="center">
<main class="card card-pad signin" id="device" data-mode="{{.Mode}}" data-code="{{.Code}}" data-app="{{.App}}" data-rd="{{.RD}}">
  <div class="brand"><img src="/admin/assets/favicon.svg" alt=""><div><div class="brand-name">Vexel</div>{{if .Tenant}}<div class="brand-tenant">{{.Tenant}}</div>{{end}}</div></div>
  {{if .Error}}
    <h1>Enrollment link not valid</h1>
    <p>{{.Error}}</p>
  {{else if eq .Mode "enroll"}}
    <h1>Enroll this device</h1>
    <p>This registers <strong>{{.DeviceName}}</strong> as a trusted device for <strong>{{.Email}}</strong>. Your device will ask for your PIN, fingerprint or face.</p>
    <p class="muted small">The key is created inside this device's security chip and never leaves it. Open this link on the device being enrolled, in the browser that will be used for work.</p>
    <div class="error-box" id="error" role="alert" hidden></div>
    <div class="notice" id="done" role="status" hidden></div>
    <button type="button" class="btn btn-primary" id="go">Enroll this device</button>
  {{else}}
    <h1>Confirm it's your company device</h1>
    <p><strong>{{.AppName}}</strong> can only be used from a trusted device. Confirm with your PIN, fingerprint or face to continue as {{.Email}}.</p>
    <div class="error-box" id="error" role="alert" hidden></div>
    <button type="button" class="btn btn-primary" id="go">Confirm with this device</button>
    <p class="muted small gap-top">Not on your enrolled device? Switch to it, or ask your administrator to enroll this one.</p>
  {{end}}
</main>
</div>
</body>
</html>`))
