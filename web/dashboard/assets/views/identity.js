import { get, put, del, APIError } from '../api.js';
import { h, clear, toast, field, pageHead, secretBox, fmtExact } from '../dom.js';

export async function render(page, session) {
  let idp = null;
  try {
    idp = await get('/identity-provider');
  } catch (err) {
    if (!(err instanceof APIError && err.status === 404)) throw err;
  }
  const reload = () => render(page, session);

  const issuer = h('input', { type: 'url', required: true, value: idp?.issuer ?? '', placeholder: 'https://login.microsoftonline.com/<tenant-id>/v2.0', autocomplete: 'off' });
  const clientID = h('input', { type: 'text', required: true, value: idp?.client_id ?? '', autocomplete: 'off', class: 'mono' });
  const secret = h('input', { type: 'password', autocomplete: 'new-password',
    placeholder: idp?.has_client_secret ? '•••••••• (unchanged)' : 'Client secret' });
  const scopes = h('input', { type: 'text', value: (idp?.scopes ?? ['openid', 'email', 'profile']).join(' '), class: 'mono' });
  const groups = h('input', { type: 'text', value: idp?.groups_claim ?? 'groups', class: 'mono' });

  const save = h('button', { type: 'submit', class: 'btn btn-primary' }, idp ? 'Save changes' : 'Connect identity provider');
  const form = h('form', { class: 'card card-pad', onsubmit: async (e) => {
    e.preventDefault();
    if (!form.reportValidity()) return;
    const body = {
      issuer: issuer.value.trim(),
      client_id: clientID.value.trim(),
      scopes: scopes.value.split(/[\s,]+/).filter(Boolean),
      groups_claim: groups.value.trim(),
    };
    if (secret.value) body.client_secret = secret.value;
    save.disabled = true;
    try {
      await put('/identity-provider', body);
      toast('Identity provider saved');
      reload();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      save.disabled = false;
    }
  } },
  h('div', { class: 'field' },
    h('label', null, 'Redirect URL'),
    secretBox(session.redirect_url),
    h('span', { class: 'hint' }, 'Register this as the redirect / callback URL in your identity provider’s app registration.')),
  field('Issuer URL', issuer, 'The OpenID Connect issuer. Vexel discovers the endpoints from it.'),
  h('div', { class: 'row' },
    field('Client ID', clientID),
    field('Client secret', secret, idp?.has_client_secret ? 'Leave blank to keep the current secret.' : 'Stored encrypted; never shown again.')),
  h('div', { class: 'row' },
    field('Scopes', scopes, 'Space separated. Must include openid.'),
    field('Groups claim', groups, 'ID token claim listing the user’s groups, used by group policies.')),
  h('div', { class: 'row' },
    h('div', null, save),
    idp ? h('div', { class: 'muted small' }, `Last changed ${fmtExact(idp.updated_at)}`) : null));

  const remove = idp ? h('button', { type: 'button', class: 'btn btn-danger', onclick: async () => {
    if (!confirm('Disconnect the identity provider? Nobody will be able to sign in until a new one is configured.')) return;
    try {
      await del('/identity-provider');
      toast('Identity provider removed');
      reload();
    } catch (err) {
      toast(err.message, 'error');
    }
  } }, 'Disconnect') : null;

  clear(page,
    pageHead('Identity provider', 'Your users sign in to apps and to this dashboard with your organisation’s OpenID Connect provider, such as Microsoft Entra ID, Google Workspace or Okta.', remove),
    idp ? null : h('div', { class: 'notice' }, 'No identity provider is connected, so nobody can sign in except through development login.'),
    form);
}
