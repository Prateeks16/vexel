import { get, post, del } from '../api.js';
import { h, clear, toast, openDialog, field, fmtTime, fmtExact, pageHead, emptyState, table, secretBox } from '../dom.js';

export async function render(page, session) {
  const [devices, enrollments, users] = await Promise.all([get('/devices'), get('/device-enrollments'), get('/users')]);
  const reload = () => render(page, session);
  const enrollBtn = () => h('button', { type: 'button', class: 'btn btn-primary', onclick: () => enroll(users, reload) }, 'Enroll a device');
  const head = pageHead('Devices',
    'Company devices trusted for apps whose policies require a trusted device. Each holds a key in its security chip (TPM or Secure Enclave) that cannot be copied to another machine.',
    enrollBtn());

  const sections = [head];
  if (devices.length === 0) {
    sections.push(emptyState('No trusted devices yet',
      'Enroll each company laptop before it is handed over. Then add a “Trusted device” rule to the apps that should only open on them.', enrollBtn()));
  } else {
    sections.push(table(['Device', 'User', 'Enrolled', 'Last used', 'Status', ''], devices.map((d) => h('tr', null,
      h('td', null, d.name, h('span', { class: 'sub mono' }, d.id)),
      h('td', null, d.user),
      h('td', { class: 'muted', title: fmtExact(d.created_at) }, fmtTime(d.created_at)),
      h('td', { class: 'muted', title: d.last_used_at ? fmtExact(d.last_used_at) : '' }, d.last_used_at ? fmtTime(d.last_used_at) : 'never'),
      h('td', null, d.revoked_at
        ? h('span', { class: 'badge badge-danger', title: fmtExact(d.revoked_at) }, 'Revoked')
        : h('span', { class: 'badge badge-ok' }, 'Trusted')),
      h('td', { class: 'actions' },
        h('a', { class: 'btn btn-sm', href: '#/access?user=' + encodeURIComponent(d.user) }, 'Activity'),
        d.revoked_at ? null : h('button', { type: 'button', class: 'btn btn-sm btn-danger', onclick: () => revoke(d, reload) }, 'Revoke'))))));
  }

  if (enrollments.length) {
    sections.push(h('h2', { class: 'section-title' }, 'Pending enrollment links'),
      table(['Device', 'For', 'Created by', 'Expires', ''], enrollments.map((e) => h('tr', null,
        h('td', null, e.name),
        h('td', null, e.user),
        h('td', { class: 'muted' }, e.created_by),
        h('td', { class: 'muted', title: fmtExact(e.expires_at) }, fmtExact(e.expires_at)),
        h('td', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-sm', onclick: () => cancel(e, reload) }, 'Cancel'))))));
  }
  clear(page, ...sections);
}

function enroll(users, reload) {
  const listID = 'user-list';
  const email = h('input', { type: 'email', required: true, list: listID, autocomplete: 'off', placeholder: 'name@company.com' });
  const name = h('input', { type: 'text', required: true, maxlength: 80, placeholder: 'e.g. Priya – ThinkPad (asset 0142)' });
  openDialog({
    title: 'Enroll a device',
    body: h('div', null,
      h('datalist', { id: listID }, users.map((u) => h('option', { value: u.email }))),
      field('User', email, 'The person who will use this device. They must sign in with this email.'),
      field('Device name', name, 'Something you can recognise later, such as the asset tag.')),
    submitLabel: 'Create enrollment link',
    onSubmit: async () => {
      const out = await post('/device-enrollments', { email: email.value.trim(), name: name.value.trim() });
      reload();
      setTimeout(() => openDialog({
        title: 'Enrollment link',
        body: h('div', null,
          h('div', { class: 'notice' }, 'Shown once. Valid for 24 hours and for one device only.'),
          secretBox(out.url),
          h('ol', { class: 'steps' },
            h('li', null, 'Open this link on the device being enrolled, in the browser that will be used for work.'),
            h('li', null, 'Click “Enroll this device” and confirm with Windows Hello or Touch ID.'),
            h('li', null, `${out.name} then appears here as trusted for ${out.user}.`))),
      }), 0);
    },
  });
}

async function revoke(d, reload) {
  if (!confirm(`Revoke ${d.name}? Apps that require a trusted device stop opening on it within seconds, even in sessions already open.`)) return;
  try {
    await post(`/devices/${d.id}/revoke`);
    toast(`${d.name} revoked`);
    reload();
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function cancel(e, reload) {
  try {
    await del('/device-enrollments/' + e.id);
    toast('Enrollment link cancelled');
    reload();
  } catch (err) {
    toast(err.message, 'error');
  }
}
