package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/Prateeks16/vexel/internal/store"
)

const (
	oidcStateCookie = "vexel_oidc_state"
	stateAudience   = "vexel:oidc-state"
)

type oidcProvider struct {
	verifier    *oidc.IDTokenVerifier
	oauth       oauth2.Config
	groupsClaim string
}

type oidcEntry struct {
	updatedAt time.Time
	provider  *oidcProvider
}

// oidcFor returns the tenant's provider, running discovery on first use and
// again whenever the tenant changes its identity provider settings.
func (s *Server) oidcFor(ctx context.Context, idp store.IdentityProvider) (*oidcProvider, error) {
	s.oidcMu.Lock()
	e, ok := s.oidc[idp.TenantID]
	s.oidcMu.Unlock()
	if ok && e.updatedAt.Equal(idp.UpdatedAt) {
		return e.provider, nil
	}

	var clientSecret string
	if idp.ClientSecretSealed != "" {
		var err error
		if clientSecret, err = s.box.Open(idp.ClientSecretSealed, idp.TenantID); err != nil {
			return nil, fmt.Errorf("oidc: open client secret: %w", err)
		}
	}
	p, err := oidc.NewProvider(ctx, idp.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %s: %w", idp.Issuer, err)
	}
	prov := &oidcProvider{
		verifier: p.Verifier(&oidc.Config{ClientID: idp.ClientID}),
		oauth: oauth2.Config{
			ClientID:     idp.ClientID,
			ClientSecret: clientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  s.cfg.PublicURL + "/auth/callback",
			Scopes:       idp.Scopes,
		},
		groupsClaim: idp.GroupsClaim,
	}
	s.oidcMu.Lock()
	s.oidc[idp.TenantID] = oidcEntry{updatedAt: idp.UpdatedAt, provider: prov}
	s.oidcMu.Unlock()
	return prov, nil
}

// stateClaims round-trips the login attempt through the IdP in a signed,
// short-lived cookie, so the control plane stays stateless.
type stateClaims struct {
	jwt.RegisteredClaims
	State    string `json:"st"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"pkce"`
	App      string `json:"app,omitempty"`    // app logins
	RD       string `json:"rd,omitempty"`     // app logins
	Tenant   string `json:"tenant,omitempty"` // dashboard logins (slug)
}

func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request, t *loginTarget, idp store.IdentityProvider) {
	p, err := s.oidcFor(r.Context(), idp)
	if err != nil {
		s.log.Error("oidc provider unavailable", "tenant", idp.TenantID, "err", err)
		http.Error(w, "the identity provider is unavailable", http.StatusBadGateway)
		return
	}
	now := time.Now()
	sc := stateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.PublicURL,
			Audience:  jwt.ClaimStrings{stateAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
	}
	if t.app != nil {
		sc.App, sc.RD = t.app.ID, t.rd.String()
	} else {
		sc.Tenant = t.tenantSlug
	}
	tok, err := s.signer.Sign(sc)
	if err != nil {
		s.loginError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    tok,
		Path:     "/auth/callback",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, p.oauth.AuthCodeURL(sc.State, oidc.Nonce(sc.Nonce), oauth2.S256ChallengeOption(sc.Verifier)), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(oidcStateCookie)
	if err != nil {
		http.Error(w, "login session expired, please try again", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Path: "/auth/callback", MaxAge: -1})

	sc := &stateClaims{}
	_, err = jwt.ParseWithClaims(c.Value, sc, s.keyfunc(r.Context()),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(s.cfg.PublicURL),
		jwt.WithAudience(stateAudience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		http.Error(w, "login session invalid, please try again", http.StatusBadRequest)
		return
	}

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "identity provider error: "+e, http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(sc.State)) != 1 {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	var t *loginTarget
	if sc.App != "" {
		t, err = s.appTarget(r, sc.App, sc.RD)
	} else {
		t, err = s.dashboardTarget(r.Context(), sc.Tenant)
	}
	if err != nil {
		s.loginError(w, err)
		return
	}
	idp, err := s.store.GetIdentityProvider(r.Context(), t.tenantID)
	if err != nil {
		s.loginError(w, err)
		return
	}
	p, err := s.oidcFor(r.Context(), idp)
	if err != nil {
		s.log.Error("oidc provider unavailable", "tenant", idp.TenantID, "err", err)
		http.Error(w, "the identity provider is unavailable", http.StatusBadGateway)
		return
	}

	oauthTok, err := p.oauth.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(sc.Verifier))
	if err != nil {
		s.log.Warn("oidc code exchange failed", "tenant", idp.TenantID, "err", err)
		http.Error(w, "could not complete login", http.StatusBadGateway)
		return
	}
	rawID, ok := oauthTok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "identity provider returned no id_token", http.StatusBadGateway)
		return
	}
	idt, err := p.verifier.Verify(r.Context(), rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(sc.Nonce)) != 1 {
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "invalid id_token claims", http.StatusUnauthorized)
		return
	}
	id, err := p.identity(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	id.TenantID = t.tenantID
	s.finishAuthentication(w, r, t, id)
}

func (p *oidcProvider) identity(claims map[string]any) (identity, error) {
	email, _ := claims["email"].(string)
	if email == "" {
		return identity{}, errors.New("identity provider did not return an email address")
	}
	if verified, ok := claims["email_verified"].(bool); ok && !verified {
		return identity{}, errors.New("email address is not verified")
	}
	var groups []string
	switch g := claims[p.groupsClaim].(type) {
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	case string:
		groups = []string{g}
	}
	return identity{Email: strings.ToLower(email), Groups: groups, Method: "oidc"}, nil
}
