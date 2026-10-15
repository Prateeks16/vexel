import { get, post, put } from '../api.js';
import { h, clear, toast, openDialog, field, fmtTime, pageHead, emptyState, table } from '../dom.js';

export async function render(page, session) {
  const users = await get('/users');
  const reload = () => render(page, session);
  const inviteBtn = () => h('button', { type: 'button', class: 'btn btn-primary', onclick: () => invite(reload) }, 'Invite user');
  const head = pageHead('Users', 'People who have signed in, or been invited. Disabling someone ends their open sessions within seconds.', inviteBtn());

  if (users.length === 0) {
    clear(page, head, emptyState('No users yet', 'Users appear here after their first sign-in.', inviteBtn()));
    return;
  }

  const rows = users.map((u) => {
    const me = u.email === session.email;
    const isAdmin = u.role === 'admin';
    const act = (label, fn, cls = '') => h('button', { type: 'button', class: 'btn btn-sm ' + cls, onclick: fn }, label);
    return h('tr', null,
      h('td', null, u.email, me ? h('span', { class: 'sub' }, 'you') : null),
      h('td', null, h('span', { class: isAdmin ? 'badge badge-accent' : 'badge' }, isAdmin ? 'Admin' : 'Member')),
      h('td', { class: 'muted' }, (u.groups || []).join(', ') || '—'),
      h('td', { class: 'muted', title: u.last_login_at || '' }, u.last_login_at ? fmtTime(u.last_login_at) : 'never'),
      h('td', null, status(u)),
      h('td', { class: 'actions' },
        h('a', { class: 'btn btn-sm', href: '#/access?user=' + encodeURIComponent(u.email) }, 'Activity'),
        act(isAdmin ? 'Make member' : 'Make admin', () => setRole(u, isAdmin ? 'member' : 'admin', me, reload)),
        u.disabled_at
          ? act('Enable', () => setDisabled(u, false, reload))
          : act('Disable', () => setDisabled(u, true, reload), 'btn-danger')));
  });
  clear(page, head, table(['Email', 'Role', 'Groups', 'Last sign-in', 'Status', ''], rows));
}

function status(u) {
  if (u.disabled_at) return h('span', { class: 'badge badge-danger' }, 'Disabled');
  if (!u.last_login_at) return h('span', { class: 'badge badge-warn' }, 'Invited');
  return h('span', { class: 'badge badge-ok' }, 'Active');
}

function invite(reload) {
  const email = h('input', { type: 'email', required: true, autocomplete: 'off', placeholder: 'name@company.com' });
  const role = h('select', null, h('option', { value: 'member' }, 'Member'), h('option', { value: 'admin' }, 'Admin'));
  openDialog({
    title: 'Invite user',
    body: h('div', null,
      field('Email', email, 'They sign in with your identity provider using this address.'),
      field('Role', role, 'Admins can use this dashboard. Members can only use apps their policies allow.')),
    submitLabel: 'Invite',
    onSubmit: async () => {
      await post('/users', { email: email.value.trim(), role: role.value });
      toast(`Invited ${email.value.trim()}`);
      reload();
    },
  });
}

async function setRole(u, role, me, reload) {
  if (me && role === 'member' && !confirm('Remove your own admin access? You will lose access to this dashboard.')) return;
  try {
    await put(`/users/${u.id}/role`, { role });
    toast(`${u.email} is now ${role === 'admin' ? 'an admin' : 'a member'}`);
    if (me && role === 'member') location.reload();
    else reload();
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function setDisabled(u, disabled, reload) {
  if (disabled && !confirm(`Disable ${u.email}? Their open sessions end at the next edge sync and they can't sign in again.`)) return;
  try {
    await post(`/users/${u.id}/${disabled ? 'disable' : 'enable'}`);
    toast(`${u.email} ${disabled ? 'disabled' : 'enabled'}`);
    reload();
  } catch (err) {
    toast(err.message, 'error');
  }
}
