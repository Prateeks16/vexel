package edge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/Prateeks16/vexel/internal/snapshot"
	"github.com/Prateeks16/vexel/internal/tunnel"
	"github.com/Prateeks16/vexel/pkg/vexelauth"
)

type transportKey struct{ app, connector, slug string }

func (s *Server) newProxy(a snapshot.App) http.Handler {
	return &httputil.ReverseProxy{
		Transport: s.transport(transportKey{a.ID, a.Connector, a.Slug}),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = a.Hostname
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()

			// Never let a client supply its own identity headers.
			for k := range pr.Out.Header {
				if strings.HasPrefix(k, "X-Vexel-") {
					pr.Out.Header.Del(k)
				}
			}
			stripCookie(pr.Out, sessionCookie)

			if fi, ok := pr.In.Context().Value(forwardKey{}).(forwardInfo); ok {
				pr.Out.Header.Set(vexelauth.AssertionHeader, fi.token)
				pr.Out.Header.Set(vexelauth.EmailHeader, fi.email)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			s.log.Warn("upstream request failed", "app", a.ID, "connector", a.Connector, "err", err)
			if errors.Is(err, tunnel.ErrNoConnector) {
				http.Error(w, "the connector for this application is offline", http.StatusBadGateway)
				return
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
}

// transport returns a pooled transport whose connections are tunnel streams.
// Transports outlive config reloads so idle upstream connections are reused.
func (s *Server) transport(key transportKey) *http.Transport {
	if t, ok := s.transports.Load(key); ok {
		return t.(*http.Transport)
	}
	t := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return s.tunnels.Dial(ctx, key.connector, key.slug)
		},
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	actual, _ := s.transports.LoadOrStore(key, t)
	return actual.(*http.Transport)
}

func (s *Server) pruneTransports(st *state) {
	live := map[transportKey]bool{}
	for _, a := range st.apps {
		live[transportKey{a.ID, a.Connector, a.Slug}] = true
	}
	s.transports.Range(func(k, v any) bool {
		if !live[k.(transportKey)] {
			s.transports.Delete(k)
			v.(*http.Transport).CloseIdleConnections()
		}
		return true
	})
}

func stripCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != name {
			r.AddCookie(c)
		}
	}
}
