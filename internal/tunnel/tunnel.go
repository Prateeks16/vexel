// Package tunnel carries traffic between the edge and connectors over a single
// outbound WebSocket per connector, multiplexed with yamux.
//
// The connector dials the edge, so customer networks never accept inbound
// connections. The edge opens one yamux stream per upstream connection and
// prefixes it with the target app ID. The connector maps app IDs to upstream
// addresses from its own local configuration, so a compromised edge cannot
// steer a connector at arbitrary hosts on the customer network.
package tunnel

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	// Path is where the edge accepts connector tunnels.
	Path = "/.vexel/tunnel"

	maxAppIDLen = 128
	// wsReadLimit must exceed yamux's largest frame (its 256 KiB stream window
	// plus header), since each yamux write becomes one WebSocket message.
	wsReadLimit = 4 << 20
)

func yamuxConfig(log *slog.Logger) *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.LogOutput = nil
	cfg.Logger = slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	return cfg
}

func writeHeader(w io.Writer, appID string) error {
	_, err := io.WriteString(w, appID+"\n")
	return err
}

func readHeader(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	appID := strings.TrimSuffix(string(line), "\n")
	if appID == "" || len(appID) > maxAppIDLen {
		return "", errors.New("tunnel: invalid stream header")
	}
	return appID, nil
}
