// Package edge implements the identity-aware proxy. Every request for a
// protected app is authenticated, checked against the app's policies, audited
// and only then forwarded down the app's connector tunnel.
package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/snapshot"
	"github.com/Prateeks16/vexel/internal/tunnel"
	"github.com/Prateeks16/vexel/pkg/jwks"
	"github.com/Prateeks16/vexel/pkg/vexelauth"
)

type Config struct {
	// ControlPlaneURL is the control plane's address as reachable from the
	// edge, used for config sync and JWKS. It may differ from the public URL
	// browsers are redirected to.
	ControlPlaneURL string
	Token           string
	CookieSecure    bool
	SyncInterval    time.Duration
}

type Server struct {
	cfg     Config
	log     *slog.Logger
	audit   *audit.Logger
	client  *http.Client
	keys    *jwks.Cache
	tunnels *tunnel.Registry

	state      atomic.Pointer[state]
	etag       string   // only touched by the sync goroutine
	transports sync.Map // transportKey -> *http.Transport

	// statusDirty asks the sync loop to report connector health now rather
	// than at the next tick, so the dashboard reflects connects promptly.
	statusDirty chan struct{}
	// syncSoon asks for an early config sync, e.g. when a token names a
	// device this edge doesn't know yet (it may have just been enrolled).
	syncSoon chan struct{}
	lastSoon atomic.Int64 // unix nanos of the last early sync request
}

type app struct {
	snapshot.App
	policies   *policy.Set
	proxy      http.Handler
	usesDevice bool
}

func (s *Server) requestSync() {
	now := time.Now().UnixNano()
	if last := s.lastSoon.Load(); now-last < int64(5*time.Second) || !s.lastSoon.CompareAndSwap(last, now) {
		return
	}
	select {
	case s.syncSoon <- struct{}{}:
	default:
	}
}

type state struct {
	snap       *snapshot.Snapshot
	verifier   *vexelauth.Verifier
	apps       map[string]*app                   // by hostname
	connectors map[string]string                 // token hash -> connector ID
	connTenant map[string]string                 // connector ID -> tenant ID
	disabled   map[string]bool                   // snapshot.UserKey -> offboarded
	devices    map[string]snapshot.TrustedDevice // by device ID
}

func New(cfg Config, log *slog.Logger, al *audit.Logger) *Server {
	cfg.ControlPlaneURL = strings.TrimRight(cfg.ControlPlaneURL, "/")
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 10 * time.Second
	}
	client := &http.Client{Timeout: 10 * time.Second}
	s := &Server{
		cfg:     cfg,
		log:     log,
		audit:   al,
		client:  client,
		keys:    jwks.NewCache(cfg.ControlPlaneURL+"/.well-known/jwks.json", client),
		tunnels: tunnel.NewRegistry(log),

		statusDirty: make(chan struct{}, 1),
		syncSoon:    make(chan struct{}, 1),
	}
	s.tunnels.OnChange = func(id, remote string, up bool) {
		typ := audit.TypeConnectorDown
		if up {
			typ = audit.TypeConnectorUp
		}
		var tenant string
		if st := s.state.Load(); st != nil {
			tenant = st.connTenant[id]
		}
		al.Emit(audit.Event{Type: typ, Tenant: tenant, Connector: id, IP: remote})
		select {
		case s.statusDirty <- struct{}{}:
		default:
		}
	}
	return s
}

// TunnelHandler accepts connector tunnels. Serve it on its own listener.
func (s *Server) TunnelHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(tunnel.Path, s.tunnels.Handler(func(token string) (string, bool) {
		st := s.state.Load()
		if st == nil {
			return "", false
		}
		id, ok := st.connectors[secret.Hash(token)]
		return id, ok
	}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	return mux
}

// Close drops every connector session.
func (s *Server) Close() { s.tunnels.Close() }

// WaitForSnapshot blocks until the first config snapshot has been loaded.
func (s *Server) WaitForSnapshot(ctx context.Context) error {
	backoff := 500 * time.Millisecond
	for {
		err := s.Sync(ctx)
		if err == nil {
			return nil
		}
		s.log.Warn("waiting for control plane", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 10*time.Second)
	}
}

// SyncLoop polls the control plane for config changes and reports connector
// health until ctx is done. The edge keeps serving its last good snapshot if
// the control plane is down.
func (s *Server) SyncLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.SyncInterval)
	defer t.Stop()
	s.reportStatus(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.statusDirty:
			s.reportStatus(ctx)
		case <-s.syncSoon:
			if err := s.Sync(ctx); err != nil {
				s.log.Warn("config sync failed", "err", err)
			}
		case <-t.C:
			if err := s.Sync(ctx); err != nil {
				s.log.Warn("config sync failed", "err", err)
			}
			s.reportStatus(ctx)
		}
	}
}

func (s *Server) reportStatus(ctx context.Context) {
	if err := s.ReportStatus(ctx); err != nil {
		s.log.Warn("connector status report failed", "err", err)
	}
}

// ReportStatus sends the control plane this edge's live connector sessions.
func (s *Server) ReportStatus(ctx context.Context) error {
	body, err := json.Marshal(map[string]any{"connectors": s.tunnels.Sessions()})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.ControlPlaneURL+"/api/v1/edge/status", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("control plane returned %s", resp.Status)
	}
	return nil
}

func (s *Server) Sync(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.ControlPlaneURL+"/api/v1/edge/config", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	if s.etag != "" && s.state.Load() != nil {
		req.Header.Set("If-None-Match", s.etag)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("control plane returned %s", resp.Status)
	}

	var snap snapshot.Snapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&snap); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	if snap.Issuer == "" || snap.AuthURL == "" {
		return errors.New("rejecting snapshot without issuer or auth URL")
	}
	st := s.compile(&snap)
	s.state.Store(st)
	s.etag = resp.Header.Get("ETag")
	s.pruneTransports(st)

	for _, id := range s.tunnels.Revoke(func(id, hash string) bool { return st.connectors[hash] == id }) {
		s.log.Warn("connector credentials revoked, session closed", "connector", id)
		s.audit.Emit(audit.Event{Type: audit.TypeConnectorEvict, Connector: id})
	}
	s.log.Info("config loaded", "version", snap.Version, "apps", len(snap.Apps), "connectors", len(snap.Connectors))
	return nil
}

// compile builds the routing state. A bad app is skipped with an error log
// instead of failing the whole snapshot, so one tenant's misconfiguration
// can't freeze config updates for every other tenant.
func (s *Server) compile(snap *snapshot.Snapshot) *state {
	st := &state{
		snap:       snap,
		verifier:   &vexelauth.Verifier{Keys: s.keys, Issuer: snap.Issuer},
		apps:       make(map[string]*app, len(snap.Apps)),
		connectors: make(map[string]string, len(snap.Connectors)),
		connTenant: make(map[string]string, len(snap.Connectors)),
		disabled:   make(map[string]bool, len(snap.DisabledUsers)),
		devices:    make(map[string]snapshot.TrustedDevice, len(snap.TrustedDevices)),
	}
	for _, d := range snap.TrustedDevices {
		st.devices[d.ID] = d
	}
	for _, c := range snap.Connectors {
		st.connectors[c.TokenSHA256] = c.ID
		st.connTenant[c.ID] = c.TenantID
	}
	for _, u := range snap.DisabledUsers {
		st.disabled[snapshot.UserKey(u.TenantID, u.Email)] = true
	}
	for _, a := range snap.Apps {
		skip := func(reason string, args ...any) {
			s.log.Error("skipping app", append([]any{"app", a.ID, "tenant", a.TenantID, "reason", reason}, args...)...)
		}
		if a.Hostname == "" || a.Slug == "" || a.TenantID == "" {
			skip("missing hostname, slug or tenant")
			continue
		}
		if _, dup := st.apps[a.Hostname]; dup {
			skip("duplicate hostname", "hostname", a.Hostname)
			continue
		}
		if st.connTenant[a.Connector] != a.TenantID {
			skip("connector missing or owned by another tenant", "connector", a.Connector)
			continue
		}
		set, err := policy.Compile(a.Policies)
		if err != nil {
			skip("invalid policies", "err", err)
			continue
		}
		st.apps[a.Hostname] = &app{App: a, policies: set, proxy: s.newProxy(a), usesDevice: policy.UsesDevice(a.Policies)}
	}
	return st
}

// ConnectorSessions reports how many live tunnel sessions a connector has.
func (s *Server) ConnectorSessions(id string) int { return s.tunnels.Connected(id) }

var (
	errNoSession    = errors.New("no session")
	errWrongTenant  = errors.New("session belongs to another tenant")
	errUserDisabled = errors.New("user is disabled")
)
