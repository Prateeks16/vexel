import { get, post, del } from '../api.js';
import { h, clear, toast, openDialog, field, fmtTime, pageHead, emptyState, table, secretBox, SLUG_PATTERN } from '../dom.js';

export async function render(page, session) {
  const tokens = await get('/tokens');
  const reload = () => render(page, session);
  const newBtn = () => h('button', { type: 'button', class: 'btn btn-primary', onclick: () => create(reload) }, 'New token');
  const head = pageHead('API tokens', 'Tokens let scripts and CI manage this organisation through the admin API. They have full admin rights; store them as secrets.', newBtn());

  if (tokens.length === 0) {
    clear(page, head, emptyState('No API tokens', 'Create one to automate Vexel from scripts or CI.', newBtn()));
    return;
  }
  const rows = tokens.map((t) => h('tr', null,
    h('td', { class: 'mono' }, t.name),
    h('td', { class: 'muted', title: t.created_at }, fmtTime(t.created_at)),
    h('td', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-sm btn-danger', onclick: () => revoke(t, reload) }, 'Revoke'))));
  clear(page, head, table(['Name', 'Created', ''], rows));
}

function create(reload) {
  const name = h('input', { type: 'text', required: true, pattern: SLUG_PATTERN, class: 'mono', placeholder: 'ci-deploy', autocomplete: 'off' });
  openDialog({
    title: 'New API token',
    body: field('Name', name, 'Describe where it will be used. Lowercase letters, digits and hyphens.'),
    submitLabel: 'Create token',
    onSubmit: async () => {
      const t = await post('/tokens', { name: name.value.trim() });
      reload();
      setTimeout(() => openDialog({
        title: `Token ${t.name} created`,
        body: h('div', null,
          h('div', { class: 'notice' }, 'Copy this token now. It is shown only once.'),
          secretBox(t.token),
          h('pre', { class: 'code' }, `curl -H "Authorization: Bearer ${t.token}" \\\n  ${location.origin}/api/v1/apps`)),
      }), 0);
    },
  });
}

async function revoke(t, reload) {
  if (!confirm(`Revoke ${t.name}? Anything using it stops working immediately.`)) return;
  try {
    await del('/tokens/' + t.id);
    toast(`Revoked ${t.name}`);
    reload();
  } catch (err) {
    toast(err.message, 'error');
  }
}
