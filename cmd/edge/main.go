// Command edge runs the identity-aware proxy and the connector tunnel endpoint.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/cli"
	"github.com/Prateeks16/vexel/internal/edge"
)

func main() {
	var (
		listen       = flag.String("listen", cli.Env("VEXEL_LISTEN", ":8080"), "address for application traffic")
		tunnelListen = flag.String("tunnel-listen", cli.Env("VEXEL_TUNNEL_LISTEN", ":8082"), "address for connector tunnels")
		cpURL        = flag.String("controlplane", cli.Env("VEXEL_CONTROLPLANE_URL", "http://localhost:8081"), "control plane URL as reachable from this edge")
		tok          = flag.String("token", os.Getenv("VEXEL_EDGE_TOKEN"), "edge credential (prefer the VEXEL_EDGE_TOKEN env var)")
		tlsCert      = flag.String("tls-cert", cli.Env("VEXEL_TLS_CERT", ""), "TLS certificate file; plain HTTP if empty")
		tlsKey       = flag.String("tls-key", cli.Env("VEXEL_TLS_KEY", ""), "TLS key file")
		cookieSecure = flag.Bool("cookie-secure", cli.EnvBool("VEXEL_COOKIE_SECURE", false), "mark session cookies Secure (required behind HTTPS)")
		syncEvery    = flag.Duration("sync-interval", cli.EnvDuration("VEXEL_SYNC_INTERVAL", 10*time.Second), "config poll interval")
		logLevel     = flag.String("log-level", cli.Env("VEXEL_LOG_LEVEL", "info"), "log level")
	)
	flag.Parse()

	log := cli.Logger(*logLevel)
	if *tok == "" {
		log.Error("an edge token is required (VEXEL_EDGE_TOKEN)")
		os.Exit(2)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Error("-tls-cert and -tls-key must be set together")
		os.Exit(2)
	}

	err := run(log, edge.Config{
		ControlPlaneURL: *cpURL,
		Token:           *tok,
		CookieSecure:    *cookieSecure || *tlsCert != "",
		SyncInterval:    *syncEvery,
	}, *listen, *tunnelListen, *tlsCert, *tlsKey)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("edge exited", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, cfg edge.Config, listen, tunnelListen, cert, key string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Audit events go to stdout (for log shipping) and to the control plane's
	// access log, which is what the dashboard searches.
	sink := audit.Multi(audit.NewJSONLines(os.Stdout), &audit.HTTPSink{
		URL:   strings.TrimRight(cfg.ControlPlaneURL, "/") + "/api/v1/edge/events",
		Token: cfg.Token,
	})
	al := audit.NewLogger(sink, log, 16384)
	defer al.Close()

	srv := edge.New(cfg, log, al)
	defer srv.Close()
	if err := srv.WaitForSnapshot(ctx); err != nil {
		return err
	}
	go srv.SyncLoop(ctx)

	return cli.Serve(ctx, log,
		cli.Listener{
			Name:     "edge",
			Server:   &http.Server{Addr: listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second},
			CertFile: cert, KeyFile: key,
		},
		cli.Listener{
			Name:     "tunnel",
			Server:   &http.Server{Addr: tunnelListen, Handler: srv.TunnelHandler(), ReadHeaderTimeout: 10 * time.Second},
			CertFile: cert, KeyFile: key,
		},
	)
}
