import { get } from '../api.js';
import { h, clear, fmtExact, pageHead, emptyState, table } from '../dom.js';

export async function render(page, session) {
  const actions = await get('/audit?limit=200');
  const refresh = h('button', { type: 'button', class: 'btn', onclick: () => render(page, session) }, 'Refresh');
  const head = pageHead('Audit log', 'Every administrative change, newest first, with who made it.', refresh);
  if (actions.length === 0) {
    clear(page, head, emptyState('Nothing yet', 'Changes made in this dashboard or through the API appear here.'));
    return;
  }
  const rows = actions.map((a) => h('tr', null,
    h('td', { class: 'muted' }, fmtExact(a.at)),
    h('td', null, a.actor),
    h('td', { class: 'mono' }, a.action),
    h('td', null, a.target || '—')));
  clear(page, head, table(['Time', 'Actor', 'Action', 'Target'], rows));
}
