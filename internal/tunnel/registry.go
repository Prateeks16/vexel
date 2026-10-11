package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/Prateeks16/vexel/internal/secret"
)

var ErrNoConnector = errors.New("tunnel: connector not connected")

// Authenticator resolves a connector bearer token to a connector ID.
type Authenticator func(token string) (connectorID string, ok bool)

type session struct {
	*yamux.Session
	tokenHash string
	info      SessionInfo
}

// SessionInfo describes one live connector session, for health reporting.
type SessionInfo struct {
	Remote      string    `json:"remote"`
	Hostname    string    `json:"hostname,omitempty"`
	Version     string    `json:"version,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
}

// Headers a connector sends when dialing, describing itself.
const (
	HeaderConnectorVersion  = "X-Vexel-Connector-Version"
	HeaderConnectorHostname = "X-Vexel-Connector-Hostname"
)

// cleanHeader keeps self-reported metadata short and printable before it is
// shown in the dashboard.
func cleanHeader(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

// Registry is the edge's view of connected connectors. A connector may hold
// several sessions at once (replicas, or a reconnect overlapping a stale
// session); streams are spread across them round-robin.
type Registry struct {
	log *slog.Logger

	// OnChange, if set, is called when a connector session comes up or goes down.
	OnChange func(connectorID, remote string, up bool)

	mu       sync.RWMutex
	sessions map[string][]*session // copy-on-write; readers never see a mutated slice
	next     atomic.Uint64
}

func NewRegistry(log *slog.Logger) *Registry {
	return &Registry{log: log, sessions: map[string][]*session{}}
}

func (r *Registry) add(id string, s *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[id] = append(slices.Clone(r.sessions[id]), s)
}

func (r *Registry) remove(id string, s *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rest := slices.DeleteFunc(slices.Clone(r.sessions[id]), func(x *session) bool { return x == s })
	if len(rest) == 0 {
		delete(r.sessions, id)
	} else {
		r.sessions[id] = rest
	}
}

// Sessions returns the live sessions of every connected connector.
func (r *Registry) Sessions() map[string][]SessionInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]SessionInfo, len(r.sessions))
	for id, ss := range r.sessions {
		for _, s := range ss {
			out[id] = append(out[id], s.info)
		}
	}
	return out
}

// Connected returns the number of live sessions for a connector.
func (r *Registry) Connected(id string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions[id])
}

// Dial opens a stream to the app named appSlug on the connector, through one
// of the connector's live sessions.
func (r *Registry) Dial(ctx context.Context, connectorID, appSlug string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	sessions := r.sessions[connectorID]
	r.mu.RUnlock()

	n := uint64(len(sessions))
	if n == 0 {
		return nil, ErrNoConnector
	}
	start := r.next.Add(1)
	lastErr := ErrNoConnector
	for i := range n {
		s := sessions[(start+i)%n]
		if s.IsClosed() {
			continue
		}
		stream, err := s.OpenStream()
		if err != nil {
			lastErr = err
			continue
		}
		if err := writeHeader(stream, appSlug); err != nil {
			stream.Close()
			lastErr = err
			continue
		}
		return stream, nil
	}
	return nil, lastErr
}

// Revoke closes every session whose credentials are no longer valid, e.g.
// after a connector is deleted or its token rotated.
func (r *Registry) Revoke(valid func(connectorID, tokenHash string) bool) []string {
	r.mu.RLock()
	var stale []*session
	var ids []string
	for id, ss := range r.sessions {
		for _, s := range ss {
			if !valid(id, s.tokenHash) {
				stale = append(stale, s)
				ids = append(ids, id)
			}
		}
	}
	r.mu.RUnlock()
	for _, s := range stale {
		s.Close()
	}
	return ids
}

// Close terminates every session.
func (r *Registry) Close() {
	r.Revoke(func(string, string) bool { return false })
}

// Handler accepts connector tunnels.
func (r *Registry) Handler(auth Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			http.Error(w, "missing connector token", http.StatusUnauthorized)
			return
		}
		id, ok := auth(token)
		if !ok {
			r.log.Warn("connector rejected", "remote", req.RemoteAddr)
			http.Error(w, "invalid connector token", http.StatusUnauthorized)
			return
		}

		ws, err := websocket.Accept(w, req, nil)
		if err != nil {
			r.log.Warn("websocket accept failed", "connector", id, "err", err)
			return
		}
		ws.SetReadLimit(wsReadLimit)
		conn := websocket.NetConn(req.Context(), ws, websocket.MessageBinary)
		ys, err := yamux.Server(conn, yamuxConfig(r.log))
		if err != nil {
			conn.Close()
			r.log.Error("yamux server failed", "connector", id, "err", err)
			return
		}

		s := &session{Session: ys, tokenHash: secret.Hash(token), info: SessionInfo{
			Remote:      req.RemoteAddr,
			Hostname:    cleanHeader(req.Header.Get(HeaderConnectorHostname)),
			Version:     cleanHeader(req.Header.Get(HeaderConnectorVersion)),
			ConnectedAt: time.Now().UTC(),
		}}
		r.add(id, s)
		r.log.Info("connector connected", "connector", id, "remote", s.info.Remote, "hostname", s.info.Hostname, "version", s.info.Version)
		if r.OnChange != nil {
			r.OnChange(id, s.info.Remote, true)
		}

		select {
		case <-ys.CloseChan():
		case <-req.Context().Done():
		}
		ys.Close()
		r.remove(id, s)
		r.log.Info("connector disconnected", "connector", id, "remote", s.info.Remote)
		if r.OnChange != nil {
			r.OnChange(id, s.info.Remote, false)
		}
	})
}
