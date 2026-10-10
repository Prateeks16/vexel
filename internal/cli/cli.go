// Package cli holds the small amount of process plumbing shared by the
// binaries: env-backed flag defaults, logging and graceful HTTP shutdown.
package cli

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func Env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func EnvBool(key string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func EnvDuration(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func Logger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

type Listener struct {
	Name     string
	Server   *http.Server
	CertFile string
	KeyFile  string
}

// Serve runs every listener until ctx is cancelled or one of them fails, then
// shuts them all down gracefully.
func Serve(ctx context.Context, log *slog.Logger, listeners ...Listener) error {
	errc := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() {
			log.Info("listening", "name", l.Name, "addr", l.Server.Addr, "tls", l.CertFile != "")
			var err error
			if l.CertFile != "" {
				err = l.Server.ListenAndServeTLS(l.CertFile, l.KeyFile)
			} else {
				err = l.Server.ListenAndServe()
			}
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errc <- err
		}()
	}

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, l := range listeners {
		l.Server.Shutdown(shutdownCtx)
	}
	return err
}
