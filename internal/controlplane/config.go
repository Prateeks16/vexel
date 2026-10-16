package controlplane

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/secret"
)

// Config is the control plane's process configuration. Tenant data (apps,
// connectors, identity providers) lives in the store and is managed through
// the admin API; Seed can bootstrap one tenant for development.
type Config struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	DevMode   bool   `yaml:"dev_mode"`

	// DatabaseURL selects Postgres; environment variables in it are expanded,
	// e.g. "${VEXEL_DATABASE_URL}". Empty means an in-memory store (dev only).
	DatabaseURL       string        `yaml:"database_url"`
	SigningKeyFile    string        `yaml:"signing_key_file"`
	EncryptionKeyFile string        `yaml:"encryption_key_file"`
	SessionDuration   time.Duration `yaml:"session_duration"`
	CookieSecure      bool          `yaml:"cookie_secure"`

	// AppsDomain is the parent domain for tenant app hostnames: an app of
	// tenant "acme" must live under *.acme.<apps_domain>.
	AppsDomain string `yaml:"apps_domain"`

	// OperatorTokenSHA256 enables the operator API (tenant management).
	OperatorTokenSHA256 string `yaml:"operator_token_sha256"`

	// EdgeTunnelURL is shown in the dashboard's connector setup instructions.
	EdgeTunnelURL string `yaml:"edge_tunnel_url"`

	// AccessLogRetention is how long access events are kept before they are
	// deleted. Defaults to 90 days.
	AccessLogRetention time.Duration `yaml:"access_log_retention"`

	// AllowSyncedDeviceCredentials accepts passkeys that sync between devices
	// (backup-eligible) as trusted devices. Off by default: a synced key
	// doesn't prove which physical device is in use.
	AllowSyncedDeviceCredentials bool `yaml:"allow_synced_device_credentials"`

	Auth  AuthConfig       `yaml:"auth"`
	Edges []EdgeCredential `yaml:"edges"`
	Seed  *Seed            `yaml:"seed"`
}

type AuthConfig struct {
	// DevLogin lets anyone sign in as any email to tenants that have no
	// identity provider. It is refused unless dev_mode is also set.
	DevLogin bool `yaml:"dev_login"`
}

type EdgeCredential struct {
	ID          string `yaml:"id"`
	TokenSHA256 string `yaml:"token_sha256"`
}

// Seed describes a tenant created at startup if its slug does not exist yet.
type Seed struct {
	Tenant struct {
		Slug string `yaml:"slug"`
		Name string `yaml:"name"`
	} `yaml:"tenant"`
	Admins     []string `yaml:"admins"` // emails invited as dashboard admins
	Connectors []struct {
		Name        string `yaml:"name"`
		TokenSHA256 string `yaml:"token_sha256"`
	} `yaml:"connectors"`
	APITokens []struct {
		Name        string `yaml:"name"`
		TokenSHA256 string `yaml:"token_sha256"`
	} `yaml:"api_tokens"`
	Apps []struct {
		Slug            string          `yaml:"slug"`
		Name            string          `yaml:"name"`
		Hostname        string          `yaml:"hostname"`
		Connector       string          `yaml:"connector"` // connector name
		SessionDuration time.Duration   `yaml:"session_duration"`
		Policies        []policy.Policy `yaml:"policies"`
	} `yaml:"apps"`
	IdentityProvider *struct {
		Issuer          string   `yaml:"issuer"`
		ClientID        string   `yaml:"client_id"`
		ClientSecretEnv string   `yaml:"client_secret_env"`
		Scopes          []string `yaml:"scopes"`
		GroupsClaim     string   `yaml:"groups_claim"`
	} `yaml:"identity_provider"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Listen == "" {
		c.Listen = ":8081"
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	c.DatabaseURL = os.ExpandEnv(c.DatabaseURL)
	c.AppsDomain = strings.ToLower(strings.Trim(c.AppsDomain, "."))
	if c.SessionDuration == 0 {
		c.SessionDuration = 24 * time.Hour
	}
	if c.AccessLogRetention == 0 {
		c.AccessLogRetention = 90 * 24 * time.Hour
	}
}

func (c *Config) validate() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("public_url must be an absolute http(s) URL")
	}
	if net.ParseIP(u.Hostname()) != nil {
		return errors.New("public_url must use a domain name, not an IP address (it is the WebAuthn relying party for device trust)")
	}
	if c.AppsDomain == "" {
		return errors.New("apps_domain is required")
	}
	if !c.DevMode {
		switch {
		case u.Scheme != "https":
			return errors.New("public_url must use https outside dev_mode")
		case c.SigningKeyFile == "":
			return errors.New("signing_key_file is required outside dev_mode")
		case c.EncryptionKeyFile == "":
			return errors.New("encryption_key_file is required outside dev_mode")
		case c.DatabaseURL == "":
			return errors.New("database_url is required outside dev_mode")
		case !c.CookieSecure:
			return errors.New("cookie_secure must be true outside dev_mode")
		case c.Auth.DevLogin:
			return errors.New("auth.dev_login requires dev_mode")
		}
	}
	if c.AccessLogRetention < 24*time.Hour {
		return errors.New("access_log_retention must be at least 24h")
	}
	if len(c.Edges) == 0 {
		return errors.New("at least one edge credential is required")
	}
	for _, e := range c.Edges {
		if e.ID == "" || !secret.ValidHash(e.TokenSHA256) {
			return fmt.Errorf("edge %q: id and a hex token_sha256 are required", e.ID)
		}
	}
	if c.OperatorTokenSHA256 != "" && !secret.ValidHash(c.OperatorTokenSHA256) {
		return errors.New("operator_token_sha256 must be a hex SHA-256 digest")
	}
	return nil
}
