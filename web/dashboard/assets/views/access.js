import { get } from '../api.js';
import { h, clear, fmtExact, pageHead, table } from '../dom.js';

const DECISIONS = [
  ['', 'All events'],
  ['access.allowed', 'Allowed'],
  ['access.denied', 'Denied'],
  ['auth.login,auth.login_denied,auth.logout,auth.device_verified', 'Sign-ins'],
  ['connector.connected,connector.disconnected,connector.revoked', 'Connectors'],
];

const RANGES = [
  ['1h', 'Last hour', 3600],
  ['24h', 'Last 24 hours', 86400],
  ['7d', 'Last 7 days', 7 * 86400],
  ['30d', 'Last 30 days', 30 * 86400],
  ['all', 'Everything retained', 0],
];

const LABELS = {
  'access.allowed': ['Allowed', 'badge-ok'],
  'access.denied': ['Denied', 'badge-danger'],
  'auth.login': ['Signed in', 'badge-accent'],
  'auth.login_denied': ['Sign-in refused', 'badge-danger'],
  'auth.logout': ['Signed out', ''],
  'auth.device_verified': ['Device confirmed', 'badge-accent'],
  'connector.connected': ['Connector up', ''],
  'connector.disconnected': ['Connector down', 'badge-warn'],
  'connector.revoked': ['Connector revoked', 'badge-warn'],
};

export async function render(page, session) {
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  const [apps, devices] = await Promise.all([get('/apps'), get('/devices')]);
  const appName = { dashboard: 'Admin dashboard', ...Object.fromEntries(apps.map((a) => [a.id, a.name])) };
  const deviceName = Object.fromEntries(devices.map((d) => [d.id, d.name]));

  const user = h('input', { type: 'search', placeholder: 'Any user', value: params.get('user') || '', 'aria-label': 'User email', autocomplete: 'off' });
  const app = h('select', { 'aria-label': 'Application' },
    h('option', { value: '' }, 'All applications'),
    apps.map((a) => h('option', { value: a.id, selected: a.id === params.get('app') }, a.name)),
    h('option', { value: 'dashboard' }, 'Admin dashboard'));
  const decision = h('select', { 'aria-label': 'Event type' }, DECISIONS.map(([v, l]) => h('option', { value: v }, l)));
  const path = h('input', { type: 'search', placeholder: 'Path contains, e.g. /clients/42', 'aria-label': 'Path contains', autocomplete: 'off' });
  const range = h('select', { 'aria-label': 'Time range' }, RANGES.map(([v, l]) => h('option', { value: v, selected: v === (params.get('range') || '24h') }, l)));
  const exportLink = h('a', { class: 'btn', href: '#', download: '' }, 'Export CSV');
  const results = h('div');
  const summary = h('p', { class: 'muted small', 'aria-live': 'polite' });

  const query = () => {
    const q = new URLSearchParams();
    if (user.value.trim()) q.set('user', user.value.trim());
    if (app.value) q.set('app', app.value);
    if (decision.value) q.set('type', decision.value);
    if (path.value.trim()) q.set('path', path.value.trim());
    const secs = RANGES.find(([v]) => v === range.value)[2];
    if (secs) q.set('from', new Date(Date.now() - secs * 1000).toISOString().replace(/\.\d+Z$/, 'Z'));
    return q;
  };

  let rows = [];
  let cursor = null;
  let generation = 0; // discards responses to superseded filters

  const row = (e) => {
    const [label, cls] = LABELS[e.type] || [e.type, ''];
    const request = e.method ? `${e.method} ${e.path || '/'}` : '';
    return h('tr', null,
      h('td', { class: 'muted', title: e.at }, fmtExact(e.at)),
      h('td', null, e.user
        ? h('a', { href: '#', onclick: (ev) => { ev.preventDefault(); user.value = e.user; load(true); } }, e.user)
        : h('span', { class: 'muted' }, '—')),
      h('td', null, appName[e.app] || e.app || h('span', { class: 'muted' }, '—')),
      h('td', { class: 'small' }, e.device ? (deviceName[e.device] || e.device.slice(0, 8)) : h('span', { class: 'muted' }, '—')),
      h('td', null, h('span', { class: 'badge ' + cls }, label)),
      h('td', { class: 'mono cell-path', title: request }, request),
      h('td', { class: 'mono' }, e.ip || ''),
      h('td', { class: 'muted small' }, e.policy || e.reason || ''));
  };

  const draw = () => {
    const more = cursor
      ? h('div', { class: 'load-more' }, h('button', { type: 'button', class: 'btn', onclick: () => load(false) }, 'Load older events'))
      : null;
    if (rows.length === 0) {
      clear(results, h('div', { class: 'card' }, h('div', { class: 'empty' }, h('h2', null, 'No matching events'), h('p', null, 'Try a wider time range or fewer filters.'))));
      summary.textContent = '';
      return;
    }
    clear(results, table(['Time', 'User', 'Application', 'Device', 'Event', 'Request', 'IP', 'Policy / reason'], rows.map(row)), more);
    summary.textContent = `Showing ${rows.length} event${rows.length === 1 ? '' : 's'}, newest first${cursor ? '' : ' (all matching)'}.`;
  };

  async function load(reset) {
    const gen = ++generation;
    const q = query();
    const csv = new URLSearchParams(q);
    csv.set('format', 'csv');
    exportLink.href = '/api/v1/access-log?' + csv;
    q.set('limit', '100');
    if (!reset && cursor) q.set('cursor', cursor);
    const res = await get('/access-log?' + q);
    if (gen !== generation) return;
    rows = reset ? res.events : rows.concat(res.events);
    cursor = res.next_cursor || null;
    draw();
  }

  let debounce;
  const soon = () => { clearTimeout(debounce); debounce = setTimeout(() => load(true), 350); };
  user.addEventListener('input', soon);
  path.addEventListener('input', soon);
  for (const el of [app, decision, range]) el.addEventListener('change', () => load(true));

  clear(page,
    pageHead('Access log', 'Every request to your apps, allowed or denied, and every sign-in: who, what, when and from where. Kept for the configured retention period, then deleted.', exportLink),
    h('div', { class: 'filters' },
      h('div', { class: 'field' }, h('label', null, 'User'), user),
      h('div', { class: 'field' }, h('label', null, 'Application'), app),
      h('div', { class: 'field' }, h('label', null, 'Event'), decision),
      h('div', { class: 'field grow' }, h('label', null, 'Path'), path),
      h('div', { class: 'field' }, h('label', null, 'Time'), range)),
    summary,
    results);
  await load(true);
}
