// Package vexelauth verifies the identity assertion the Vexel edge attaches to
// every request it forwards. Applications behind Vexel should verify the
// assertion instead of trusting the network path alone.
//
//	keys := jwks.NewCache("https://auth.example.com/.well-known/jwks.json", nil)
//	v := &vexelauth.Verifier{Keys: keys, Issuer: "https://auth.example.com"}
//	http.Handle("/", v.Middleware("crm.example.com", app))
package vexelauth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// AssertionHeader carries the signed identity token for the request.
	AssertionHeader = "X-Vexel-Assertion"
	// EmailHeader is a convenience copy of the user's email. Only trust it
	// after the assertion has been verified.
	EmailHeader = "X-Vexel-User-Email"
)

type Claims struct {
	jwt.RegisteredClaims
	TenantID string   `json:"tid"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups,omitempty"`
	// DeviceID is set when the user proved, at sign-in, that they are on an
	// enrolled trusted device.
	DeviceID string `json:"did,omitempty"`
	// DeviceChecked records that sign-in ran the device check for this app
	// (whether or not a device was found), so edges know a fresh sign-in
	// would not change the outcome.
	DeviceChecked bool `json:"dchk,omitempty"`
}

type KeySource interface {
	Key(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

type Verifier struct {
	Keys   KeySource
	Issuer string
}

// Verify checks the token's signature, issuer, expiry and that it was issued
// for audience.
func (v *Verifier) Verify(ctx context.Context, raw, audience string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid")
		}
		return v.Keys.Key(ctx, kid)
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	if claims.Email == "" {
		return nil, errors.New("token has no email")
	}
	return claims, nil
}

type contextKey struct{}

// Middleware rejects requests without a valid assertion for audience and
// makes the verified claims available through FromContext.
func (v *Verifier) Middleware(audience string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(AssertionHeader)
		if raw == "" {
			http.Error(w, "missing identity assertion", http.StatusUnauthorized)
			return
		}
		claims, err := v.Verify(r.Context(), raw, audience)
		if err != nil {
			http.Error(w, "invalid identity assertion", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, claims)))
	})
}

func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(contextKey{}).(*Claims)
	return c, ok
}
