// Command connector runs inside the customer network and tunnels traffic from
// the edge to local applications. It only makes outbound connections.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/Prateeks16/vexel/internal/cli"
	"github.com/Prateeks16/vexel/internal/tunnel"
)

// upstreams is a repeatable app=host:port flag.
type upstreams map[string]string

func (u upstreams) String() string {
	parts := make([]string, 0, len(u))
	for k, v := range u {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (u upstreams) Set(v string) error {
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		app, addr, ok := strings.Cut(item, "=")
		if !ok || app == "" || addr == "" {
			return fmt.Errorf("upstream %q: want app=host:port", item)
		}
		u[app] = addr
	}
	return nil
}

func main() {
	ups := upstreams{}
	if env := os.Getenv("VEXEL_UPSTREAMS"); env != "" {
		if err := ups.Set(env); err != nil {
			fmt.Fprintln(os.Stderr, "VEXEL_UPSTREAMS:", err)
			os.Exit(2)
		}
	}
	edgeURL := flag.String("edge", cli.Env("VEXEL_EDGE_URL", "ws://localhost:8082/.vexel/tunnel"), "edge tunnel URL (wss:// in production)")
	tok := flag.String("token", os.Getenv("VEXEL_CONNECTOR_TOKEN"), "connector credential (prefer the VEXEL_CONNECTOR_TOKEN env var)")
	logLevel := flag.String("log-level", cli.Env("VEXEL_LOG_LEVEL", "info"), "log level")
	flag.Var(ups, "upstream", "app=host:port to serve; repeatable or comma separated (env VEXEL_UPSTREAMS)")
	flag.Parse()

	log := cli.Logger(*logLevel)
	if *tok == "" {
		log.Error("a connector token is required (VEXEL_CONNECTOR_TOKEN)")
		os.Exit(2)
	}
	if len(ups) == 0 {
		log.Error("at least one -upstream is required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c := &tunnel.Client{EdgeURL: *edgeURL, Token: *tok, Upstreams: ups, Log: log}
	if err := c.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("connector exited", "err", err)
		os.Exit(1)
	}
}
