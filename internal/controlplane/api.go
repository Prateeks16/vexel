package controlplane

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/store"
)

func (s *Server) routeAPI() {
	op := s.operatorAPI
	s.mux.Handle("GET /api/v1/operator/tenants", op(s.apiListTenants))
	s.mux.Handle("POST /api/v1/operator/tenants", op(s.apiCreateTenant))
	s.mux.Handle("POST /api/v1/operator/tenants/{tenant}/tokens", op(s.apiOperatorCreateToken))

	t := s.tenantAPI
	s.mux.Handle("GET /api/v1/tenant", t(s.apiGetTenant))
	s.mux.Handle("GET /api/v1/session", t(s.apiSession))

	s.mux.Handle("GET /api/v1/apps", t(s.apiListApps))
	s.mux.Handle("POST /api/v1/apps", t(s.apiCreateApp))
	s.mux.Handle("GET /api/v1/apps/{id}", t(s.apiGetApp))
	s.mux.Handle("PUT /api/v1/apps/{id}", t(s.apiUpdateApp))
	s.mux.Handle("DELETE /api/v1/apps/{id}", t(s.apiDeleteApp))

	s.mux.Handle("GET /api/v1/connectors", t(s.apiListConnectors))
	s.mux.Handle("POST /api/v1/connectors", t(s.apiCreateConnector))
	s.mux.Handle("POST /api/v1/connectors/{id}/rotate", t(s.apiRotateConnector))
	s.mux.Handle("DELETE /api/v1/connectors/{id}", t(s.apiDeleteConnector))

	s.mux.Handle("GET /api/v1/identity-provider", t(s.apiGetIDP))
	s.mux.Handle("PUT /api/v1/identity-provider", t(s.apiPutIDP))
	s.mux.Handle("DELETE /api/v1/identity-provider", t(s.apiDeleteIDP))

	s.mux.Handle("GET /api/v1/users", t(s.apiListUsers))
	s.mux.Handle("POST /api/v1/users", t(s.apiInviteUser))
	s.mux.Handle("PUT /api/v1/users/{id}/role", t(s.apiSetUserRole))
	s.mux.Handle("POST /api/v1/users/{id}/disable", t(s.apiSetUserDisabled(true)))
	s.mux.Handle("POST /api/v1/users/{id}/enable", t(s.apiSetUserDisabled(false)))

	s.mux.Handle("GET /api/v1/tokens", t(s.apiListTokens))
	s.mux.Handle("POST /api/v1/tokens", t(s.apiCreateToken))
	s.mux.Handle("DELETE /api/v1/tokens/{id}", t(s.apiDeleteToken))

	s.mux.Handle("GET /api/v1/audit", t(s.apiListAudit))
	s.mux.Handle("GET /api/v1/access-log", t(s.apiAccessLog))

	s.mux.Handle("GET /api/v1/devices", t(s.apiListDevices))
	s.mux.Handle("POST /api/v1/devices/{id}/revoke", t(s.apiRevokeDevice))
	s.mux.Handle("GET /api/v1/device-enrollments", t(s.apiListEnrollments))
	s.mux.Handle("POST /api/v1/device-enrollments", t(s.apiCreateEnrollment))
	s.mux.Handle("DELETE /api/v1/device-enrollments/{id}", t(s.apiDeleteEnrollment))
}

// Authentication

type tenantRequest struct {
	tenant  store.Tenant
	actor   Actor
	session *sessionClaims // set for dashboard (cookie) requests
	user    *store.User    // set for dashboard (cookie) requests
}

type tenantHandler func(w http.ResponseWriter, r *http.Request, tr tenantRequest) error

// apiAuthError is an authentication or authorisation failure.
type apiAuthError struct {
	status int
	msg    string
}

func (e *apiAuthError) Error() string { return e.msg }

func unauthorized(msg string) error { return &apiAuthError{http.StatusUnauthorized, msg} }
func forbidden(msg string) error    { return &apiAuthError{http.StatusForbidden, msg} }

// tenantAPI authenticates either a tenant API token (automation) or a
// dashboard session cookie belonging to an active admin. Every handler behind
// it only ever sees its own tenant.
func (s *Server) tenantAPI(h tenantHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tr tenantRequest
		var err error
		if raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			tr, err = s.authToken(r, raw)
		} else {
			tr, err = s.authSession(r)
		}
		if err == nil {
			err = h(w, r, tr)
		}
		if err != nil {
			s.apiError(w, err)
		}
	})
}

func (s *Server) authToken(r *http.Request, raw string) (tenantRequest, error) {
	if raw == "" {
		return tenantRequest{}, unauthorized("missing bearer token")
	}
	tok, err := s.store.APITokenByHash(r.Context(), secret.Hash(raw))
	if errors.Is(err, store.ErrNotFound) {
		return tenantRequest{}, unauthorized("invalid token")
	}
	if err != nil {
		return tenantRequest{}, err
	}
	tenant, err := s.store.GetTenant(r.Context(), tok.TenantID)
	if err != nil {
		return tenantRequest{}, err
	}
	return tenantRequest{tenant: tenant, actor: tokenActor(tok)}, nil
}

// authSession authenticates a dashboard request. The cookie alone is never
// enough to change anything: state-changing requests must also carry the
// session's CSRF secret, which a cross-site page cannot read, and must not
// come from another origin. The admin role is re-checked on every request so
// demotion and offboarding take effect immediately.
func (s *Server) authSession(r *http.Request) (tenantRequest, error) {
	sc, ok := s.parseSession(r)
	if !ok {
		return tenantRequest{}, unauthorized("not signed in")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if sc.CSRF == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sc.CSRF)) != 1 {
			return tenantRequest{}, forbidden("missing or invalid CSRF token")
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != s.publicOrigin {
			return tenantRequest{}, forbidden("cross-origin request refused")
		}
	}
	tenant, err := s.store.GetTenant(r.Context(), sc.TenantID)
	if err != nil {
		return tenantRequest{}, err
	}
	u, err := s.store.GetUserByEmail(r.Context(), sc.TenantID, sc.Email)
	if errors.Is(err, store.ErrNotFound) {
		return tenantRequest{}, unauthorized("not signed in")
	}
	if err != nil {
		return tenantRequest{}, err
	}
	switch {
	case u.DisabledAt != nil:
		return tenantRequest{}, forbidden("your account has been disabled")
	case u.Role != store.RoleAdmin:
		return tenantRequest{}, forbidden(fmt.Sprintf("signed in as %s, who is not an administrator of %s", u.Email, tenant.Name))
	}
	return tenantRequest{tenant: tenant, actor: userActor(u.Email), session: sc, user: &u}, nil
}

func (s *Server) operatorAPI(h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.OperatorTokenSHA256 == "" {
			http.NotFound(w, r)
			return
		}
		raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" || subtle.ConstantTimeCompare([]byte(secret.Hash(raw)), []byte(s.cfg.OperatorTokenSHA256)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "invalid operator token")
			return
		}
		if err := h(w, r); err != nil {
			s.apiError(w, err)
		}
	})
}

// Encoding

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) apiError(w http.ResponseWriter, err error) {
	var inv *invalidError
	var ae *apiAuthError
	switch {
	case errors.As(err, &ae):
		writeJSONError(w, ae.status, ae.msg)
	case errors.As(err, &inv):
		writeJSONError(w, http.StatusBadRequest, inv.msg)
	case errors.Is(err, store.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrConflict):
		writeJSONError(w, http.StatusConflict, err.Error())
	default:
		s.log.Error("admin api", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("invalid JSON body: %v", err)
	}
	return nil
}

// Operator

func (s *Server) apiListTenants(w http.ResponseWriter, r *http.Request) error {
	ts, err := s.store.ListTenants(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, ts)
}

func (s *Server) apiCreateTenant(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Slug       string `json:"slug"`
		Name       string `json:"name"`
		AdminEmail string `json:"admin_email"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	t, err := s.admin.CreateTenant(r.Context(), ActorOperator, body.Slug, body.Name, body.AdminEmail)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, t)
}

func (s *Server) apiOperatorCreateToken(w http.ResponseWriter, r *http.Request) error {
	tenant, err := s.store.GetTenantBySlug(r.Context(), r.PathValue("tenant"))
	if err != nil {
		return err
	}
	return s.createToken(w, r, tenant, ActorOperator)
}

// Tenant

func (s *Server) apiGetTenant(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	return writeJSON(w, http.StatusOK, tr.tenant)
}

// apiSession describes the caller. The dashboard loads it first to learn
// who is signed in and to obtain the CSRF token for later writes.
func (s *Server) apiSession(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	out := map[string]any{
		"actor":           tr.actor,
		"tenant":          tr.tenant,
		"apps_domain":     s.cfg.AppsDomain,
		"edge_tunnel_url": s.cfg.EdgeTunnelURL,
		"redirect_url":    s.cfg.PublicURL + "/auth/callback",
	}
	if tr.session != nil {
		out["email"] = tr.user.Email
		out["role"] = tr.user.Role
		out["csrf_token"] = tr.session.CSRF
		out["expires_at"] = tr.session.ExpiresAt.Time
	}
	return writeJSON(w, http.StatusOK, out)
}

// Apps

type appJSON struct {
	ID              string          `json:"id,omitempty"`
	Slug            string          `json:"slug"`
	Name            string          `json:"name"`
	Hostname        string          `json:"hostname"`
	ConnectorID     string          `json:"connector_id"`
	SessionDuration string          `json:"session_duration,omitempty"`
	Policies        []policy.Policy `json:"policies"`
	CreatedAt       *time.Time      `json:"created_at,omitempty"`
	UpdatedAt       *time.Time      `json:"updated_at,omitempty"`
}

func toAppJSON(a store.App) appJSON {
	return appJSON{
		ID: a.ID, Slug: a.Slug, Name: a.Name, Hostname: a.Hostname, ConnectorID: a.ConnectorID,
		SessionDuration: a.SessionDuration.String(), Policies: a.Policies,
		CreatedAt: &a.CreatedAt, UpdatedAt: &a.UpdatedAt,
	}
}

func (j appJSON) input() (AppInput, error) {
	in := AppInput{Slug: j.Slug, Name: j.Name, Hostname: j.Hostname, ConnectorID: j.ConnectorID, Policies: j.Policies}
	if j.SessionDuration != "" {
		d, err := time.ParseDuration(j.SessionDuration)
		if err != nil {
			return AppInput{}, invalid("session_duration: %v", err)
		}
		in.SessionDuration = d
	}
	return in, nil
}

func (s *Server) apiListApps(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	apps, err := s.store.ListApps(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	out := make([]appJSON, len(apps))
	for i, a := range apps {
		out[i] = toAppJSON(a)
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiCreateApp(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	var body appJSON
	if err := decode(r, &body); err != nil {
		return err
	}
	in, err := body.input()
	if err != nil {
		return err
	}
	app, err := s.admin.CreateApp(r.Context(), tr.actor, tr.tenant, in)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, toAppJSON(app))
}

func (s *Server) apiGetApp(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	app, err := s.store.GetApp(r.Context(), tr.tenant.ID, r.PathValue("id"))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, toAppJSON(app))
}

func (s *Server) apiUpdateApp(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	var body appJSON
	if err := decode(r, &body); err != nil {
		return err
	}
	in, err := body.input()
	if err != nil {
		return err
	}
	app, err := s.admin.UpdateApp(r.Context(), tr.actor, tr.tenant, r.PathValue("id"), in)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, toAppJSON(app))
}

func (s *Server) apiDeleteApp(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	if err := s.admin.DeleteApp(r.Context(), tr.actor, tr.tenant, r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Connectors

type connectorJSON struct {
	store.Connector
	Token  string           `json:"token,omitempty"` // only on create and rotate
	Status *connectorHealth `json:"status,omitempty"`
}

type connectorHealth struct {
	Online   bool                     `json:"online"`
	Sessions []store.ConnectorSession `json:"sessions"`
}

func (s *Server) apiListConnectors(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	cs, err := s.store.ListConnectors(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	live, err := s.connectorStatus(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	out := make([]connectorJSON, len(cs))
	for i, c := range cs {
		sessions := live[c.ID]
		if sessions == nil {
			sessions = []store.ConnectorSession{}
		}
		out[i] = connectorJSON{Connector: c, Status: &connectorHealth{Online: len(sessions) > 0, Sessions: sessions}}
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiCreateConnector(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	var body struct {
		Name string `json:"name"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	c, tok, err := s.admin.CreateConnector(r.Context(), tr.actor, tr.tenant, body.Name)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, connectorJSON{Connector: c, Token: tok})
}

func (s *Server) apiRotateConnector(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	tok, err := s.admin.RotateConnector(r.Context(), tr.actor, tr.tenant, r.PathValue("id"))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func (s *Server) apiDeleteConnector(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	if err := s.admin.DeleteConnector(r.Context(), tr.actor, tr.tenant, r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Identity provider

type idpJSON struct {
	Issuer          string     `json:"issuer"`
	ClientID        string     `json:"client_id"`
	ClientSecret    *string    `json:"client_secret,omitempty"` // write-only
	HasClientSecret bool       `json:"has_client_secret"`       // read-only
	Scopes          []string   `json:"scopes,omitempty"`
	GroupsClaim     string     `json:"groups_claim,omitempty"`
	RedirectURL     string     `json:"redirect_url,omitempty"` // read-only: register this with the IdP
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

func (s *Server) toIDPJSON(idp store.IdentityProvider) idpJSON {
	return idpJSON{
		Issuer: idp.Issuer, ClientID: idp.ClientID, HasClientSecret: idp.ClientSecretSealed != "",
		Scopes: idp.Scopes, GroupsClaim: idp.GroupsClaim, RedirectURL: s.cfg.PublicURL + "/auth/callback",
		UpdatedAt: &idp.UpdatedAt,
	}
}

func (s *Server) apiGetIDP(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	idp, err := s.store.GetIdentityProvider(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, s.toIDPJSON(idp))
}

func (s *Server) apiPutIDP(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	var body idpJSON
	if err := decode(r, &body); err != nil {
		return err
	}
	idp, err := s.admin.PutIdentityProvider(r.Context(), tr.actor, tr.tenant, IDPInput{
		Issuer: body.Issuer, ClientID: body.ClientID, ClientSecret: body.ClientSecret,
		Scopes: body.Scopes, GroupsClaim: body.GroupsClaim,
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, s.toIDPJSON(idp))
}

func (s *Server) apiDeleteIDP(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	if err := s.admin.DeleteIdentityProvider(r.Context(), tr.actor, tr.tenant); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Users

func (s *Server) apiListUsers(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	us, err := s.store.ListUsers(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, us)
}

func (s *Server) apiInviteUser(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	u, err := s.admin.InviteUser(r.Context(), tr.actor, tr.tenant, body.Email, body.Role)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, u)
}

func (s *Server) apiSetUserRole(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	var body struct {
		Role string `json:"role"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	u, err := s.admin.SetUserRole(r.Context(), tr.actor, tr.tenant, r.PathValue("id"), body.Role)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, u)
}

func (s *Server) apiSetUserDisabled(disabled bool) tenantHandler {
	return func(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
		u, err := s.admin.SetUserDisabled(r.Context(), tr.actor, tr.tenant, r.PathValue("id"), disabled)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, u)
	}
}

// Devices

func (s *Server) apiListDevices(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	devs, err := s.store.ListDevices(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, devs)
}

func (s *Server) apiRevokeDevice(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	d, err := s.admin.RevokeDevice(r.Context(), tr.actor, tr.tenant, r.PathValue("id"))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, d)
}

func (s *Server) apiListEnrollments(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	es, err := s.store.ListDeviceEnrollments(r.Context(), tr.tenant.ID, time.Now())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, es)
}

func (s *Server) apiCreateEnrollment(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	var body struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	e, code, err := s.admin.CreateDeviceEnrollment(r.Context(), tr.actor, tr.tenant, body.Email, body.Name)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, struct {
		store.DeviceEnrollment
		URL string `json:"url"` // shown once
	}{e, s.cfg.PublicURL + "/device/enroll?code=" + url.QueryEscape(code)})
}

func (s *Server) apiDeleteEnrollment(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	if err := s.admin.DeleteDeviceEnrollment(r.Context(), tr.actor, tr.tenant, r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// API tokens

type tokenJSON struct {
	store.APIToken
	Token string `json:"token"`
}

func (s *Server) apiListTokens(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	ts, err := s.store.ListAPITokens(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, ts)
}

func (s *Server) apiCreateToken(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	return s.createToken(w, r, tr.tenant, tr.actor)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, tenant store.Tenant, actor Actor) error {
	var body struct {
		Name string `json:"name"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	t, tok, err := s.admin.CreateAPIToken(r.Context(), actor, tenant, body.Name)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, tokenJSON{APIToken: t, Token: tok})
}

func (s *Server) apiDeleteToken(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	if err := s.admin.DeleteAPIToken(r.Context(), tr.actor, tr.tenant, r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Audit

func (s *Server) apiListAudit(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return invalid("limit must be between 1 and 1000")
		}
		limit = n
	}
	actions, err := s.store.ListAdminActions(r.Context(), tr.tenant.ID, limit)
	if err != nil {
		return fmt.Errorf("list admin actions: %w", err)
	}
	return writeJSON(w, http.StatusOK, actions)
}
