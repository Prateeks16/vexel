# Vexel

Multi-tenant zero-trust access for private applications. Put an internal app
(a CRM, an admin panel, an API) behind Vexel and it is only reachable by
signed-in, policy-approved users of that tenant. The app itself never accepts
inbound internet traffic.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): design, security properties, roadmap
- [docs/API.md](docs/API.md): admin and operator API
- [web/README.md](web/README.md): the admin dashboard

## Quick start (Docker)

```sh
docker compose up --build
```

Open <http://whoami.acme.localhost:8080>, sign in on the dev login page as
`you@example.com`, and the demo app shows the identity Vexel forwarded.
Try group `contractors` or a non-`example.com` email to see policy denials.

**Admin dashboard:** <http://localhost:8081/admin/>, organisation `acme`,
sign in as `admin@example.com`. From there you can publish apps, edit
policies, create connectors and watch their status, invite and offboard
users, search the access log (who opened what, when, from where) and export
it as CSV, connect an identity provider and issue API tokens.

The stack seeds tenant `acme` (see `configs/dev.yaml`) into Postgres. Manage
it with the dev API token:

```sh
curl -H "Authorization: Bearer dev-api-token" localhost:8081/api/v1/apps
curl -H "Authorization: Bearer dev-api-token" localhost:8081/api/v1/users
```

Disable a user with `POST /api/v1/users/{id}/disable` and their open session
stops working within one edge sync (10s by default).

**Trusted devices:** in the dashboard, open **Devices → Enroll a device**,
open the link on your laptop and confirm with Windows Hello / Touch ID. Then
add a *Trusted device* rule to an app's policy: it opens only on enrolled
devices, asks for the device at sign-in, and stops opening on a device as
soon as you revoke it.

## Quick start (Go, no database)

Without `VEXEL_DATABASE_URL` the control plane uses an in-memory store. Run
each in its own terminal from the repo root:

```sh
go run ./cmd/controlplane -config configs/dev.yaml
VEXEL_EDGE_TOKEN=dev-edge-token go run ./cmd/edge
go run ./examples/whoami
VEXEL_CONNECTOR_TOKEN=dev-connector-token go run ./cmd/connector -upstream whoami=localhost:9000
```

On Windows PowerShell set env vars with `$env:VEXEL_EDGE_TOKEN="dev-edge-token"` first.

## Layout

```
cmd/
  controlplane/   login, tokens, JWKS, edge config API, admin API
  edge/           identity-aware proxy + connector tunnel endpoint
  connector/      runs in the customer network, dials out to the edge
  vexelctl/       operator CLI (tokens, signing and encryption keys)
internal/
  controlplane/   config, per-tenant OIDC + dev login, admin service + API, seeding
  store/          Postgres + in-memory stores, migrations, conformance suite
  edge/           routing, session check, policy, audit, reverse proxy
  tunnel/         WebSocket + yamux transport, connector registry
  policy/         include / require / exclude policy engine
  snapshot/       config model pushed from control plane to edges
  audit/          buffered audit event pipeline
  token/ secret/  JWT signing, token hashing, secret encryption
pkg/
  vexelauth/      SDK for apps to verify the X-Vexel-Assertion header
  jwks/           JWK encoding and a caching JWKS client
examples/whoami/  demo upstream app
configs/          dev and example production configs
test/e2e/         login → policy → tunnel → app, offboarding, API-created apps
test/ui/          dashboard smoke test in headless Chrome
web/              admin dashboard (embedded, served at /admin/)
```

## Development

```sh
go test ./...        # unit + end-to-end tests (in-memory store)
go vet ./...

# Also run the store suite against Postgres:
docker run -d --rm --name vexel-pg -e POSTGRES_PASSWORD=vexel -p 55432:5432 postgres:17-alpine
VEXEL_TEST_DATABASE_URL="postgres://postgres:vexel@localhost:55432/postgres?sslmode=disable" go test ./internal/store/
```

`make race` needs cgo (Linux/macOS, or a C toolchain on Windows). CI runs the
race detector and the Postgres suite.

## Operating

```sh
go run ./cmd/vexelctl token                  # edge/connector/operator token + hash
go run ./cmd/vexelctl keygen signing.pem     # JWT signing key
go run ./cmd/vexelctl enckey encryption.key  # key for sealing IdP secrets
```

Production configs must set `dev_mode: false`, which enforces https, Secure
cookies, Postgres, and persistent signing and encryption keys. See
`configs/production.example.yaml`.

### Protecting your own app

Verify the assertion in your app instead of trusting the network path:

```go
keys := jwks.NewCache("https://auth.example.com/.well-known/jwks.json", nil)
v := &vexelauth.Verifier{Keys: keys, Issuer: "https://auth.example.com"}
http.Handle("/", v.Middleware("crm.acme.vexel.app", yourHandler))
```
