import { get, setCSRF, APIError } from './api.js';
import { h, clear, toast, TENANT_PATTERN } from './dom.js';
import * as apps from './views/apps.js';
import * as connectors from './views/connectors.js';
import * as users from './views/users.js';
import * as identity from './views/identity.js';
import * as tokens from './views/tokens.js';
import * as audit from './views/audit.js';
import * as access from './views/access.js';
import * as devices from './views/devices.js';

const routes = [
  { path: 'apps', label: 'Applications', view: apps },
  { path: 'connectors', label: 'Connectors', view: connectors },
  { path: 'users', label: 'Users', view: users },
  { path: 'devices', label: 'Devices', view: devices },
  { path: 'access', label: 'Access log', view: access },
  { path: 'identity', label: 'Identity provider', view: identity },
  { path: 'tokens', label: 'API tokens', view: tokens },
  { path: 'audit', label: 'Audit log', view: audit },
];

const root = document.getElementById('root');
const LAST_TENANT = 'vexel.lastTenant';

function remember(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key) || '';
    localStorage.setItem(key, value);
  } catch {
    return '';
  }
}

function brand(sub) {
  return h('div', { class: 'brand' },
    h('img', { src: 'assets/favicon.svg', alt: '' }),
    h('div', null, h('div', { class: 'brand-name' }, 'Vexel'), sub ? h('div', { class: 'brand-tenant' }, sub) : null));
}

async function signOut() {
  try {
    await fetch('/auth/logout', { credentials: 'same-origin' });
  } finally {
    location.hash = '';
    location.reload();
  }
}

function renderSignIn(message) {
  const input = h('input', { type: 'text', id: 'tenant', required: true, autocomplete: 'organization', placeholder: 'acme', value: remember(LAST_TENANT), pattern: TENANT_PATTERN });
  const form = h('form', { class: 'card card-pad signin', onsubmit: (e) => {
    e.preventDefault();
    const slug = input.value.trim().toLowerCase();
    if (!slug) return;
    remember(LAST_TENANT, slug);
    location.href = '/admin/login?tenant=' + encodeURIComponent(slug);
  } },
  brand(),
  h('h1', null, 'Sign in to the admin dashboard'),
  h('p', null, message || 'Enter your organisation ID. You will sign in with your organisation’s identity provider.'),
  h('div', { class: 'field' }, h('label', { for: 'tenant' }, 'Organisation ID'), input),
  h('button', { type: 'submit', class: 'btn btn-primary' }, 'Continue'));
  clear(root, h('div', { class: 'center' }, form));
  input.focus();
}

function renderNoAccess(message) {
  clear(root, h('div', { class: 'center' },
    h('div', { class: 'card card-pad signin' },
      brand(),
      h('h1', null, 'No access'),
      h('p', null, message),
      h('button', { type: 'button', class: 'btn', onclick: signOut }, 'Sign out'))));
}

function renderShell(session) {
  const nav = h('nav', { class: 'nav', 'aria-label': 'Sections' },
    routes.map((r) => h('a', { href: '#/' + r.path, 'data-path': r.path }, r.label)));
  const main = h('main', { class: 'main', id: 'main', tabindex: '-1' });
  clear(root, h('div', { class: 'shell' },
    h('aside', { class: 'sidebar' },
      brand(session.tenant.name),
      nav,
      h('div', { class: 'sidebar-foot' },
        h('div', { class: 'who' }, session.email),
        h('button', { type: 'button', class: 'btn btn-sm', onclick: signOut }, 'Sign out'))),
    main));

  const show = async () => {
    const path = location.hash.replace(/^#\/?/, '').split(/[/?]/)[0] || 'apps';
    const route = routes.find((r) => r.path === path) || routes[0];
    for (const a of nav.querySelectorAll('a')) {
      if (a.dataset.path === route.path) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    document.title = `${route.label} · ${session.tenant.name} · Vexel`;
    const page = h('div', { class: 'page' }, h('p', { class: 'muted' }, 'Loading…'));
    clear(main, page);
    try {
      await route.view.render(page, session);
    } catch (err) {
      if (err instanceof APIError && err.status === 401) return;
      clear(page, h('div', { class: 'error-box', role: 'alert' }, err.message || String(err)));
    }
  };
  window.addEventListener('hashchange', show);
  show();
}

async function boot() {
  window.addEventListener('vexel:signed-out', () => renderSignIn('Your session has ended. Please sign in again.'));
  let session;
  try {
    session = await get('/session');
  } catch (err) {
    if (err instanceof APIError && err.status === 401) return renderSignIn();
    if (err instanceof APIError && err.status === 403) return renderNoAccess(err.message);
    clear(root, h('div', { class: 'center' }, h('div', { class: 'error-box' }, 'Could not reach the control plane: ' + err.message)));
    return;
  }
  if (!session.csrf_token) {
    toast('This dashboard needs a browser session; API tokens are for automation.', 'error');
    return renderSignIn();
  }
  setCSRF(session.csrf_token);
  remember(LAST_TENANT, session.tenant.slug);
  renderShell(session);
}

boot();
