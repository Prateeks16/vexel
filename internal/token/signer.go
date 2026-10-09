// Package token signs the JWTs issued by the control plane.
package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Prateeks16/vexel/pkg/jwks"
)

// Signer holds the active ES256 signing key. It also implements
// vexelauth.KeySource so the control plane can verify its own tokens without
// a network round trip.
type Signer struct {
	key *ecdsa.PrivateKey
	jwk jwks.Key
}

func NewSigner(key *ecdsa.PrivateKey) (*Signer, error) {
	jwk, err := jwks.FromECDSA(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, jwk: jwk}, nil
}

func (s *Signer) Sign(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = s.jwk.Kid
	return t.SignedString(s.key)
}

func (s *Signer) JWKS() jwks.Set {
	return jwks.Set{Keys: []jwks.Key{s.jwk}}
}

func (s *Signer) Key(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
	if kid != s.jwk.Kid {
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	return &s.key.PublicKey, nil
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func EncodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key: expected a PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("signing key: must be an ECDSA P-256 key")
	}
	return key, nil
}
