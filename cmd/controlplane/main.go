// Command controlplane runs login, token issuance, the edge config API and
// the tenant admin API.
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/cli"
	"github.com/Prateeks16/vexel/internal/controlplane"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/store"
	"github.com/Prateeks16/vexel/internal/token"
)

func main() {
	configPath := flag.String("config", cli.Env("VEXEL_CONFIG", "configs/dev.yaml"), "path to the control plane config file")
	logLevel := flag.String("log-level", cli.Env("VEXEL_LOG_LEVEL", "info"), "log level: debug, info, warn, error")
	flag.Parse()

	log := cli.Logger(*logLevel)
	if err := run(log, *configPath); err != nil {
		log.Error("control plane exited", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, configPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := controlplane.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.DevMode {
		log.Warn("running in dev mode: do not expose this instance")
	}

	st, err := openStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()

	key, err := signingKey(cfg, log)
	if err != nil {
		return err
	}
	signer, err := token.NewSigner(key)
	if err != nil {
		return err
	}
	box, err := encryptionBox(cfg, log)
	if err != nil {
		return err
	}

	access, ok := st.(store.AccessLog)
	if !ok {
		return errors.New("store does not provide an access log")
	}
	al := audit.NewLogger(audit.Multi(audit.NewJSONLines(os.Stdout), controlplane.AccessLogSink(access)), log, 4096)
	defer al.Close()

	srv, err := controlplane.New(cfg, controlplane.Deps{Store: st, AccessLog: access, Signer: signer, Box: box, Log: log, Audit: al})
	if err != nil {
		return err
	}
	if err := srv.Seed(ctx); err != nil {
		return err
	}
	go srv.RunRetention(ctx)
	return cli.Serve(ctx, log, cli.Listener{
		Name:   "controlplane",
		Server: &http.Server{Addr: cfg.Listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second},
	})
}

func openStore(ctx context.Context, cfg *controlplane.Config, log *slog.Logger) (store.Store, error) {
	if cfg.DatabaseURL == "" {
		log.Warn("no database_url set, using an in-memory store; all data is lost on restart")
		return store.NewMemory(), nil
	}
	pg, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := pg.Migrate(ctx); err != nil {
		pg.Close()
		return nil, err
	}
	log.Info("connected to postgres, migrations applied")
	return pg, nil
}

func signingKey(cfg *controlplane.Config, log *slog.Logger) (*ecdsa.PrivateKey, error) {
	if cfg.SigningKeyFile != "" {
		return token.LoadKey(cfg.SigningKeyFile)
	}
	log.Warn("no signing_key_file set, using an ephemeral key; sessions will not survive a restart")
	return token.GenerateKey()
}

func encryptionBox(cfg *controlplane.Config, log *slog.Logger) (*secret.Box, error) {
	if cfg.EncryptionKeyFile != "" {
		key, err := secret.LoadKey(cfg.EncryptionKeyFile)
		if err != nil {
			return nil, err
		}
		return secret.NewBox(key)
	}
	log.Warn("no encryption_key_file set, using an ephemeral key; stored IdP secrets will be unreadable after a restart")
	return secret.NewBox(secret.GenerateKey())
}
