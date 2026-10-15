# Admin dashboard

A dependency-free single-page app (plain ES modules, no build step) embedded
in the control plane binary via `web.go` and served at `/admin/`.

- **Auth:** admins sign in through their tenant's own identity provider, the
  same login flow apps use (`/admin/login?tenant=<slug>`). The control plane
  session cookie then authenticates `/api/v1` calls; every state-changing
  call must also send the session's CSRF token (`X-CSRF-Token`, from
  `GET /api/v1/session`) and pass an Origin check. The admin role is
  re-checked on every request.
- **Same API as automation:** the dashboard uses exactly the endpoints in
  `docs/API.md`, so nothing is dashboard-only.
- **Safe rendering:** all DOM is built with `h()` in `assets/dom.js` using text
  nodes; there is no `innerHTML`. A strict CSP (`script-src 'self'`, no
  inline script, no third-party origins) is set by the control plane.

Layout:

```
dashboard/
  index.html
  assets/
    app.js            shell, sign-in, hash router
    api.js            fetch wrapper (CSRF, errors)
    dom.js            h(), dialogs, toasts, formatting, input patterns
    policy-editor.js  ordered include / require / exclude editor
    device.js         enrollment and sign-in device check (WebAuthn)
    views/            apps, connectors, users, devices, access, identity, tokens, audit
    app.css           light + dark themes, phone layout
```

Smoke test in a real browser: `test/ui/`.

Screens: applications (with policy editor), connectors (live status),
users, devices (enrollment links, revoke), access log (filters, CSV export), identity provider, API tokens, admin
audit log. Planned: device posture, billing.
