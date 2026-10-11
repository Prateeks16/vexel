package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/Prateeks16/vexel/internal/version"
)

// Client is the connector side of the tunnel. It keeps a session to the edge
// open, reconnecting with backoff, and forwards each stream to a local
// upstream.
type Client struct {
	EdgeURL   string            // e.g. wss://edge.example.com/.vexel/tunnel
	Token     string            // connector bearer token
	Upstreams map[string]string // app ID -> host:port on the local network
	Log       *slog.Logger

	// OnConnect, if set, is called each time a session is established.
	OnConnect func()
}

var errUnauthorized = errors.New("edge rejected the connector token")

func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		started := time.Now()
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		wait := backoff/2 + rand.N(backoff)
		c.Log.Warn("tunnel down", "err", err, "retry_in", wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (c *Client) connect(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	hostname, _ := os.Hostname()
	ws, resp, err := websocket.Dial(dialCtx, c.EdgeURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":         {"Bearer " + c.Token},
			HeaderConnectorVersion:  {version.Version},
			HeaderConnectorHostname: {hostname},
		},
	})
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return errUnauthorized
		}
		return err
	}
	ws.SetReadLimit(wsReadLimit)
	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	sess, err := yamux.Client(conn, yamuxConfig(c.Log))
	if err != nil {
		conn.Close()
		return err
	}
	defer sess.Close()

	c.Log.Info("tunnel up", "edge", c.EdgeURL, "apps", len(c.Upstreams))
	if c.OnConnect != nil {
		c.OnConnect()
	}
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return fmt.Errorf("session closed: %w", err)
		}
		go c.handle(ctx, stream)
	}
}

func (c *Client) handle(ctx context.Context, stream net.Conn) {
	defer stream.Close()
	br := bufio.NewReaderSize(stream, 512)
	appID, err := readHeader(br)
	if err != nil {
		c.Log.Warn("bad stream header", "err", err)
		return
	}
	addr, ok := c.Upstreams[appID]
	if !ok {
		c.Log.Warn("stream for app not served by this connector", "app", appID)
		return
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	up, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		c.Log.Warn("upstream dial failed", "app", appID, "addr", addr, "err", err)
		return
	}
	defer up.Close()
	pipe(stream, br, up)
}

// pipe copies in both directions, propagating half-closes so HTTP keep-alive
// and upgraded connections terminate cleanly.
func pipe(stream net.Conn, fromStream io.Reader, up net.Conn) {
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(up, fromStream)
		closeWrite(up)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(stream, up)
		closeWrite(stream)
		errc <- err
	}()
	if err := <-errc; err != nil {
		return // the caller's deferred Close tears down both directions
	}
	<-errc
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	// A yamux stream's Close is already a half-close (it sends FIN).
	c.Close()
}
