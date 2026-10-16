// Package controlplane serves login, token issuance, JWKS, the config API
// that edges sync from, and the tenant admin API.
package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/snapshot"
	"github.com/Prateeks16/vexel/internal/store"
	"github.com/Prateeks16/vexel/internal/token"
	"github.com/Prateeks16/vexel/pkg/vexelauth"
)

type Deps struct {
	Store     store.Store
	AccessLog store.AccessLog
	Signer    *token.Signer
	Box       *secret.Box
	Log       *slog.Logger
	Audit     *audit.Logger
}

type Server struct {
	cfg      *Config
	store    store.Store
	access   store.AccessLog
	signer   *token.Signer
	box      *secret.Box
	log      *slog.Logger
	audit    *audit.Logger
	verifier *vexelauth.Verifier
	admin    *admin
	webauthn *webauthn.WebAuthn

	edgeTokens   map[string]string // token hash -> edge ID
	publicOrigin string            // scheme://host of PublicURL, for Origin checks

	snapMu sync.Mutex
	snap   atomic.Pointer[builtSnapshot]

	oidcMu sync.Mutex
	oidc   map[string]oidcEntry // tenant ID -> provider

	mux *http.ServeMux
}

func New(cfg *Config, d Deps) (*Server, error) {
	if d.Store == nil || d.AccessLog == nil || d.Signer == nil || d.Box == nil || d.Log == nil || d.Audit == nil {
		return nil, errors.New("controlplane: all dependencies are required")
	}
	s := &Server{
		cfg:        cfg,
		store:      d.Store,
		access:     d.AccessLog,
		signer:     d.Signer,
		box:        d.Box,
		log:        d.Log,
		audit:      d.Audit,
		verifier:   &vexelauth.Verifier{Keys: d.Signer, Issuer: cfg.PublicURL},
		admin:      &admin{store: d.Store, box: d.Box, appsDomain: cfg.AppsDomain, devMode: cfg.DevMode, log: d.Log},
		edgeTokens: map[string]string{},
		oidc:       map[string]oidcEntry{},
		mux:        http.NewServeMux(),
	}
	for _, e := range cfg.Edges {
		s.edgeTokens[e.TokenSHA256] = e.ID
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	s.publicOrigin = u.Scheme + "://" + u.Host
	if s.webauthn, err = newWebAuthn(cfg); err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	s.mux.HandleFunc("GET /api/v1/edge/config", s.handleEdgeConfig)
	s.mux.HandleFunc("POST /api/v1/edge/events", s.handleEdgeEvents)
	s.mux.HandleFunc("POST /api/v1/edge/status", s.handleEdgeStatus)
	s.mux.HandleFunc("GET /auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /auth/dev-login", s.handleDevLogin)
	s.mux.HandleFunc("GET /auth/callback", s.handleCallback)
	s.mux.HandleFunc("GET /auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /auth/device", s.handleDevicePage)
	s.mux.HandleFunc("POST /auth/device/begin", s.handleDeviceBegin)
	s.mux.HandleFunc("POST /auth/device/finish", s.handleDeviceFinish)
	s.mux.HandleFunc("GET /device/enroll", s.handleEnrollPage)
	s.mux.HandleFunc("POST /device/enroll/begin", s.handleEnrollBegin)
	s.mux.HandleFunc("POST /device/enroll/finish", s.handleEnrollFinish)
	s.routeAPI()
	if err := s.routeDashboard(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(s.signer.JWKS())
}

// edgeID authenticates an edge by its bearer token.
func (s *Server) edgeID(r *http.Request) (string, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return "", false
	}
	id, known := s.edgeTokens[secret.Hash(tok)]
	return id, known
}

func (s *Server) handleEdgeConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.edgeID(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	b, err := s.currentSnapshot(r.Context())
	if err != nil {
		s.log.Error("build snapshot", "err", err)
		http.Error(w, "config unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("ETag", b.etag)
	if r.Header.Get("If-None-Match") == b.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b.body)
}

// builtSnapshot is the edge config at one store revision, plus indexes the
// login flow uses.
type builtSnapshot struct {
	revision int64
	body     []byte
	etag     string
	apps     map[string]*snapshot.App          // by app ID
	disabled map[string]bool                   // snapshot.UserKey
	devices  map[string]snapshot.TrustedDevice // by device ID
}

// currentSnapshot returns the snapshot for the store's current revision,
// rebuilding it only when the revision has moved. Revisions live in the
// store, so every control plane replica agrees on them.
func (s *Server) currentSnapshot(ctx context.Context) (*builtSnapshot, error) {
	rev, err := s.store.Revision(ctx)
	if err != nil {
		return nil, err
	}
	if b := s.snap.Load(); b != nil && b.revision == rev {
		return b, nil
	}
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if b := s.snap.Load(); b != nil && b.revision >= rev {
		return b, nil
	}
	data, err := s.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	b, err := s.buildSnapshot(data)
	if err != nil {
		return nil, err
	}
	s.snap.Store(b)
	return b, nil
}

func (s *Server) buildSnapshot(data store.Snapshot) (*builtSnapshot, error) {
	snap := snapshot.Snapshot{
		Issuer:        s.cfg.PublicURL,
		AuthURL:       s.cfg.PublicURL,
		Apps:          make([]snapshot.App, 0, len(data.Apps)),
		Connectors:    make([]snapshot.Connector, 0, len(data.Connectors)),
		DisabledUsers: make([]snapshot.DisabledUser, 0, len(data.DisabledUsers)),

		TrustedDevices: make([]snapshot.TrustedDevice, 0, len(data.TrustedDevices)),
	}
	b := &builtSnapshot{revision: data.Revision, apps: map[string]*snapshot.App{}, disabled: map[string]bool{}, devices: map[string]snapshot.TrustedDevice{}}

	for _, a := range data.Apps {
		// Apps are validated on write; this guards against rows written by an
		// older or newer version with different policy rules.
		if _, err := policy.Compile(a.Policies); err != nil {
			s.log.Error("excluding app with invalid policies from snapshot", "app", a.ID, "tenant", a.TenantID, "err", err)
			continue
		}
		snap.Apps = append(snap.Apps, snapshot.App{
			ID: a.ID, TenantID: a.TenantID, Slug: a.Slug, Name: a.Name, Hostname: a.Hostname,
			Connector: a.ConnectorID, SessionDuration: a.SessionDuration, Policies: a.Policies,
		})
	}
	for _, c := range data.Connectors {
		snap.Connectors = append(snap.Connectors, snapshot.Connector{ID: c.ID, TenantID: c.TenantID, TokenSHA256: c.TokenSHA256})
	}
	for _, u := range data.DisabledUsers {
		snap.DisabledUsers = append(snap.DisabledUsers, snapshot.DisabledUser{TenantID: u.TenantID, Email: u.Email})
		b.disabled[snapshot.UserKey(u.TenantID, u.Email)] = true
	}
	for _, d := range data.TrustedDevices {
		td := snapshot.TrustedDevice{ID: d.DeviceID, TenantID: d.TenantID, Email: d.UserEmail}
		snap.TrustedDevices = append(snap.TrustedDevices, td)
		b.devices[td.ID] = td
	}

	body, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	snap.Version = fmt.Sprintf("%d-%s", data.Revision, hex.EncodeToString(sum[:6]))
	if b.body, err = json.Marshal(snap); err != nil {
		return nil, err
	}
	b.etag = `"` + snap.Version + `"`
	for i := range snap.Apps {
		b.apps[snap.Apps[i].ID] = &snap.Apps[i]
	}
	return b, nil
}
