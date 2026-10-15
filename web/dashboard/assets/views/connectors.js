import { get, post, del } from '../api.js';
import { h, clear, toast, openDialog, field, fmtTime, pageHead, emptyState, table, secretBox, SLUG_PATTERN } from '../dom.js';

export async function render(page, session) {
  const [connectors, apps] = await Promise.all([get('/connectors'), get('/apps')]);
  const reload = () => render(page, session);
  const newBtn = () => h('button', { type: 'button', class: 'btn btn-primary', onclick: () => createConnector(session, reload) }, 'New connector');
  const head = pageHead('Connectors', 'A connector runs inside your network next to your apps and opens an outbound tunnel to Vexel. No inbound ports are needed.', newBtn());

  if (connectors.length === 0) {
    clear(page, head, emptyState('No connectors yet', 'Create one, then run it on a machine that can reach your apps.', newBtn()));
    return;
  }

  const rows = connectors.map((c) => {
    const used = apps.filter((a) => a.connector_id === c.id);
    return h('tr', null,
      h('td', null, c.name, h('span', { class: 'sub mono' }, c.id)),
      h('td', null, statusCell(c)),
      h('td', null, used.length ? used.map((a) => a.slug).join(', ') : h('span', { class: 'muted' }, 'none')),
      h('td', { class: 'muted', title: c.created_at }, fmtTime(c.created_at)),
      h('td', { class: 'actions' },
        h('button', { type: 'button', class: 'btn btn-sm', onclick: () => rotate(session, c, reload) }, 'Rotate token'),
        h('button', { type: 'button', class: 'btn btn-sm btn-danger', disabled: used.length > 0,
          title: used.length ? 'Move or delete its apps first' : null,
          onclick: () => remove(c, reload) }, 'Delete')));
  });
  clear(page, head, table(['Name', 'Status', 'Serves', 'Created', ''], rows));

  // Keep status fresh while this page is open, without disturbing an open
  // dialog. Only the newest render keeps refreshing, so manual reloads don't
  // stack timers; navigating away detaches the page and stops the cycle.
  const gen = (refreshGen.get(page) || 0) + 1;
  refreshGen.set(page, gen);
  const tick = () => {
    if (!page.isConnected || refreshGen.get(page) !== gen) return;
    if (document.querySelector('dialog[open]')) return setTimeout(tick, 10000);
    render(page, session).catch(() => {});
  };
  setTimeout(tick, 10000);
}

const refreshGen = new WeakMap();

function statusCell(c) {
  const st = c.status || { online: false, sessions: [] };
  if (!st.online) {
    return h('span', null, h('span', { class: 'status-dot off', 'aria-hidden': 'true' }), 'Offline',
      h('span', { class: 'sub' }, 'No tunnel to any edge'));
  }
  const s = st.sessions;
  const hosts = [...new Set(s.map((x) => x.hostname).filter(Boolean))].join(', ');
  const versions = [...new Set(s.map((x) => x.version).filter(Boolean))].join(', ');
  const detail = [`${s.length} session${s.length === 1 ? '' : 's'}`, hosts, versions].filter(Boolean).join(' · ');
  return h('span', null, h('span', { class: 'status-dot on', 'aria-hidden': 'true' }),
    h('a', { href: '#', onclick: (e) => { e.preventDefault(); showSessions(c); } }, 'Online'),
    h('span', { class: 'sub' }, detail));
}

function showSessions(c) {
  openDialog({
    title: `${c.name}: live sessions`,
    wide: true,
    body: table(['Edge', 'Host', 'Version', 'From', 'Connected'], c.status.sessions.map((s) => h('tr', null,
      h('td', { class: 'mono' }, s.edge),
      h('td', null, s.hostname || '—'),
      h('td', { class: 'mono' }, s.version || '—'),
      h('td', { class: 'mono' }, s.remote),
      h('td', { class: 'muted', title: s.connected_at }, fmtTime(s.connected_at))))),
  });
}

function createConnector(session, reload) {
  const name = h('input', { type: 'text', required: true, pattern: SLUG_PATTERN, class: 'mono', placeholder: 'office-dc-1', autocomplete: 'off' });
  openDialog({
    title: 'New connector',
    body: field('Name', name, 'Lowercase letters, digits and hyphens.'),
    submitLabel: 'Create connector',
    onSubmit: async () => {
      const c = await post('/connectors', { name: name.value.trim() });
      reload();
      setTimeout(() => showToken(session, `Connector ${c.name} created`, c.token), 0);
    },
  });
}

function showToken(session, title, token) {
  const edge = session.edge_tunnel_url || '<edge tunnel URL>';
  const cmd = `VEXEL_CONNECTOR_TOKEN=${token} \\\n  connector -edge ${edge} \\\n  -upstream <app-slug>=<host:port>`;
  openDialog({
    title,
    body: h('div', null,
      h('div', { class: 'notice' }, 'Copy this token now. It is shown only once and cannot be recovered.'),
      secretBox(token),
      h('p', { class: 'muted small' }, 'Run the connector on a machine that can reach your apps:'),
      h('pre', { class: 'code' }, cmd)),
  });
}

async function rotate(session, c, reload) {
  if (!confirm(`Issue a new token for ${c.name}? The running connector is disconnected at the next edge sync until it is restarted with the new token.`)) return;
  try {
    const { token } = await post(`/connectors/${c.id}/rotate`);
    reload();
    showToken(session, `New token for ${c.name}`, token);
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function remove(c, reload) {
  if (!confirm(`Delete connector ${c.name}?`)) return;
  try {
    await del('/connectors/' + c.id);
    toast(`Deleted ${c.name}`);
    reload();
  } catch (err) {
    toast(err.message, 'error');
  }
}
