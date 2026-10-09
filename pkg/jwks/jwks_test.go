package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := FromECDSA(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Fatal("decoded key does not match original")
	}
	k2, _ := FromECDSA(&priv.PublicKey)
	if k.Kid != k2.Kid {
		t.Fatal("thumbprint must be deterministic")
	}
}

func TestCacheRateLimitsUnknownKids(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, _ := FromECDSA(&priv.PublicKey)

	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		json.NewEncoder(w).Encode(Set{Keys: []Key{k}})
	}))
	defer srv.Close()

	c := NewCache(srv.URL, srv.Client())
	ctx := context.Background()
	if _, err := c.Key(ctx, k.Kid); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := c.Key(ctx, "bogus"); err == nil {
			t.Fatal("expected error for unknown kid")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("expected 1 fetch, got %d", n)
	}
}
