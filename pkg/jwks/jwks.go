// Package jwks encodes ECDSA P-256 public keys as JSON Web Keys and caches
// key sets fetched from a remote JWKS endpoint.
package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type Key struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type Set struct {
	Keys []Key `json:"keys"`
}

// FromECDSA returns the JWK for a P-256 public key. The key ID is the
// RFC 7638 thumbprint, so it is stable for a given key.
func FromECDSA(pub *ecdsa.PublicKey) (Key, error) {
	if pub.Curve != elliptic.P256() {
		return Key{}, errors.New("jwks: only P-256 keys are supported")
	}
	raw, err := pub.Bytes()
	if err != nil {
		return Key{}, err
	}
	enc := base64.RawURLEncoding
	k := Key{Kty: "EC", Crv: "P-256", X: enc.EncodeToString(raw[1:33]), Y: enc.EncodeToString(raw[33:65]), Use: "sig", Alg: "ES256"}
	// RFC 7638 requires the required members in lexical order, no whitespace.
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, k.Crv, k.Kty, k.X, k.Y)
	sum := sha256.Sum256([]byte(canonical))
	k.Kid = enc.EncodeToString(sum[:])
	return k, nil
}

func (k Key) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("jwks: unsupported key type %s/%s", k.Kty, k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwks: bad x coordinate: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("jwks: bad y coordinate: %w", err)
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("jwks: bad coordinate length")
	}
	raw := make([]byte, 0, 65)
	raw = append(raw, 4)
	raw = append(raw, x...)
	raw = append(raw, y...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
}

// Cache fetches a remote key set on demand and keeps it in memory.
type Cache struct {
	url        string
	client     *http.Client
	minRefresh time.Duration

	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

func NewCache(url string, client *http.Client) *Cache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Cache{url: url, client: client, minRefresh: 30 * time.Second, keys: map[string]*ecdsa.PublicKey{}}
}

// Key returns the public key with the given ID, refetching the key set when
// the ID is unknown. Refetches are rate limited so tokens carrying bogus key
// IDs cannot be used to hammer the JWKS endpoint.
func (c *Cache) Key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return k, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < c.minRefresh {
		return nil, fmt.Errorf("jwks: unknown key %q", kid)
	}
	c.fetchedAt = time.Now()
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("jwks: unknown key %q", kid)
}

func (c *Cache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: fetch: unexpected status %s", resp.Status)
	}
	var set Set
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := k.PublicKey()
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	c.keys = keys
	return nil
}
