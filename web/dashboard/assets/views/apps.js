import { get, post, put, del } from '../api.js';
import { h, clear, toast, openDialog, field, fmtTime, fmtDuration, slugify, pageHead, emptyState, table, SLUG_PATTERN, HOST_PATTERN } from '../dom.js';
import { policyEditor } from '../policy-editor.js';

const SESSION_CHOICES = [['1h', '1 hour'], ['4h', '4 hours'], ['8h', '8 hours'], ['12h', '12 hours'], ['24h', '24 hours'], ['168h', '7 days']];

export async function render(page, session) {
  const [apps, connectors] = await Promise.all([get('/apps'), get('/connectors')]);
  const connName = Object.fromEntries(connectors.map((c) => [c.id, c.name]));
  const connOnline = Object.fromEntries(connectors.map((c) => [c.id, !!c.status?.online]));
  const reload = () => render(page, session);

  const newBtn = () => h('button', { type: 'button', class: 'btn btn-primary', disabled: connectors.length === 0,
    title: connectors.length === 0 ? 'Create a connector first' : null,
    onclick: () => editApp(session, connectors, null, reload) }, 'New application');

  const head = pageHead('Applications', 'Private apps published through Vexel. Users reach them at their hostname after signing in and passing the app’s policies.', newBtn());

  if (apps.length === 0) {
    const hint = connectors.length === 0
      ? h('a', { href: '#/connectors', class: 'btn btn-primary' }, 'Create a connector')
      : newBtn();
    clear(page, head, emptyState('No applications yet',
      connectors.length === 0 ? 'Apps are reached through a connector running next to them. Set one up first.' : 'Publish your first private app.', hint));
    return;
  }

  const rows = apps.map((a) => h('tr', { class: 'clickable', tabindex: '0',
    onclick: () => editApp(session, connectors, a, reload),
    onkeydown: (e) => { if (e.key === 'Enter') editApp(session, connectors, a, reload); } },
  h('td', null, a.name, h('span', { class: 'sub mono' }, a.slug)),
  h('td', { class: 'mono' }, a.hostname),
  h('td', null, connName[a.connector_id] || h('span', { class: 'muted' }, 'unknown'),
    connOnline[a.connector_id] ? null : h('span', { class: 'sub' }, h('span', { class: 'status-dot off', 'aria-hidden': 'true' }), 'connector offline')),
  h('td', null, fmtDuration(a.session_duration)),
  h('td', null, policySummary(a.policies)),
  h('td', { class: 'muted', title: a.updated_at }, fmtTime(a.updated_at))));

  clear(page, head, table(['Name', 'Hostname', 'Connector', 'Session', 'Policies', 'Updated'], rows));
}

function policySummary(policies) {
  if (!policies || policies.length === 0) return h('span', { class: 'badge badge-danger', title: 'No policies: nobody can access this app' }, 'No access');
  const allows = policies.filter((p) => p.action === 'allow').length;
  const denies = policies.length - allows;
  return h('span', null,
    allows ? h('span', { class: 'badge badge-ok' }, `${allows} allow`) : null,
    allows && denies ? ' ' : null,
    denies ? h('span', { class: 'badge badge-warn' }, `${denies} deny`) : null);
}

function editApp(session, connectors, app, reload) {
  const suffix = `.${session.tenant.slug}.${session.apps_domain}`;
  const isNew = !app;
  let slugTouched = !isNew;

  const name = h('input', { type: 'text', required: true, value: app?.name ?? '', maxlength: 100, autocomplete: 'off' });
  const slug = h('input', { type: 'text', required: true, value: app?.slug ?? '', pattern: SLUG_PATTERN, class: 'mono', autocomplete: 'off',
    oninput: () => { slugTouched = true; } });
  const hostPrefix = h('input', { id: 'host-prefix', type: 'text', required: true, class: 'mono', autocomplete: 'off',
    value: app ? app.hostname.slice(0, -suffix.length) : '', pattern: HOST_PATTERN });
  name.addEventListener('input', () => {
    if (slugTouched) return;
    slug.value = slugify(name.value);
    if (isNew) hostPrefix.value = slug.value;
  });

  const connector = h('select', { required: true },
    connectors.map((c) => h('option', { value: c.id, selected: c.id === app?.connector_id }, c.name)));

  const current = app ? fmtDuration(app.session_duration) : '8h';
  const choices = SESSION_CHOICES.some(([v]) => v === current) ? SESSION_CHOICES : [[current, current], ...SESSION_CHOICES];
  const sessionSel = h('select', null, choices.map(([v, label]) => h('option', { value: v, selected: v === current }, label)));

  const policies = policyEditor(app?.policies ?? [{ name: 'Staff', action: 'allow', include: [{ email_domain: '' }] }]);

  const body = h('div', null,
    h('div', { class: 'row' },
      field('Name', name),
      field('Slug', slug, 'Also the name the connector serves it under.')),
    h('div', { class: 'field' },
      h('label', { for: 'host-prefix' }, 'Hostname'),
      h('div', { class: 'affix' }, hostPrefix, h('span', null, suffix))),
    h('div', { class: 'row' },
      field('Connector', connector),
      field('Session length', sessionSel, 'How long a sign-in lasts before re-authenticating.')),
    policies.el,
    h('p', { class: 'hint muted small' }, 'On the connector host, serve this app with ', h('span', { class: 'mono' }, '-upstream <slug>=<host:port>'), '.'));

  const extra = isNew ? [] : [h('button', { type: 'button', class: 'btn btn-danger', onclick: async () => {
    if (!confirm(`Delete ${app.name}? Users will lose access immediately after the next edge sync.`)) return;
    try {
      await del('/apps/' + app.id);
      dlg.close();
      toast(`Deleted ${app.name}`);
      reload();
    } catch (err) {
      toast(err.message, 'error');
    }
  } }, 'Delete')];

  const dlg = openDialog({
    title: isNew ? 'New application' : `Edit ${app.name}`,
    wide: true,
    body,
    extra,
    submitLabel: isNew ? 'Create application' : 'Save changes',
    onSubmit: async () => {
      const payload = {
        name: name.value.trim(),
        slug: slug.value.trim(),
        hostname: hostPrefix.value.trim().toLowerCase() + suffix,
        connector_id: connector.value,
        session_duration: sessionSel.value,
        policies: policies.value(),
      };
      if (isNew) await post('/apps', payload);
      else await put('/apps/' + app.id, payload);
      toast(isNew ? `Created ${payload.name}` : `Saved ${payload.name}`);
      reload();
    },
  });
}
