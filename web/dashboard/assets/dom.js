// DOM helpers. Text always goes through text nodes, never innerHTML, so
// tenant-supplied names and hostnames can't inject markup.

// HTML pattern attributes are compiled with the RegExp v flag, where a
// literal hyphen inside a character class must be escaped.
export const SLUG_PATTERN = String.raw`[a-z0-9]([a-z0-9\-]{0,38}[a-z0-9])?`;
export const HOST_PATTERN = String.raw`[a-z0-9]([a-z0-9.\-]*[a-z0-9])?`;
export const TENANT_PATTERN = String.raw`[a-z0-9\-]+`;

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  let value;
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'value') value = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (typeof v === 'boolean') el.toggleAttribute(k, v);
    else el.setAttribute(k, String(v));
  }
  append(el, children);
  if (value !== undefined) el.value = value;
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
}

export function clear(el, ...children) {
  el.replaceChildren();
  append(el, children);
}

export function toast(message, kind = 'info') {
  const el = h('div', { class: kind === 'error' ? 'toast toast-error' : 'toast' }, message);
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), kind === 'error' ? 7000 : 3500);
}

// openDialog shows a modal form. onSubmit may throw to keep the dialog open
// and display the error; returning normally closes it.
export function openDialog({ title, body, submitLabel = 'Save', danger, onSubmit, extra = [], wide = false, cancelLabel = 'Cancel' }) {
  const error = h('div', { class: 'error-box', hidden: true, role: 'alert' });
  const submit = onSubmit ? h('button', { type: 'submit', class: danger ? 'btn btn-danger' : 'btn btn-primary' }, submitLabel) : null;
  const dlg = h('dialog', { class: wide ? 'wide' : null, 'aria-label': title },
    h('form', { class: 'dialog-form', method: 'dialog', novalidate: true },
      h('div', { class: 'dialog-head' }, h('h2', null, title)),
      h('div', { class: 'dialog-body' }, error, body),
      h('div', { class: 'dialog-foot' },
        extra.length ? h('span', { class: 'spacer' }, extra) : null,
        h('button', { type: 'button', class: 'btn', onclick: () => dlg.close() }, onSubmit ? cancelLabel : 'Close'),
        submit),
    ));
  const form = dlg.querySelector('form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!onSubmit) return dlg.close();
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    error.hidden = true;
    submit.disabled = true;
    try {
      await onSubmit();
      dlg.close();
    } catch (err) {
      error.textContent = err.message || String(err);
      error.hidden = false;
      error.scrollIntoView({ block: 'nearest' });
    } finally {
      submit.disabled = false;
    }
  });
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  return dlg;
}

export function field(label, control, hint) {
  if (!control.id) control.id = 'f' + Math.random().toString(36).slice(2, 9);
  return h('div', { class: 'field' },
    h('label', { for: control.id }, label),
    control,
    hint ? h('span', { class: 'hint' }, hint) : null);
}

// secretBox shows a value that is only available once, with a copy button.
export function secretBox(value) {
  const input = h('input', { type: 'text', readonly: true, value, 'aria-label': 'Secret value' });
  const btn = h('button', { type: 'button', class: 'btn' , onclick: () => copy(value, input) }, 'Copy');
  return h('div', { class: 'secret-box' }, input, btn);
}

export async function copy(text, fallbackInput) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard');
  } catch {
    if (fallbackInput) {
      fallbackInput.select();
      toast('Press Ctrl+C to copy');
    }
  }
}

export function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const secs = (Date.now() - d.getTime()) / 1000;
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} h ago`;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function fmtExact(iso) {
  return iso ? new Date(iso).toLocaleString() : '';
}

// fmtDuration turns Go durations like "8h0m0s" into "8h".
export function fmtDuration(d) {
  if (!d) return '—';
  return d.replace(/(\d)h0m0s$/, '$1h').replace(/(\d)m0s$/, '$1m').replace(/^0h/, '');
}

export function slugify(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
}

export function pageHead(title, description, ...actions) {
  return h('div', { class: 'page-head' },
    h('div', null, h('h1', null, title), description ? h('p', null, description) : null),
    actions.length ? h('div', null, actions) : null);
}

export function emptyState(title, text, action) {
  return h('div', { class: 'card' }, h('div', { class: 'empty' }, h('h2', null, title), h('p', null, text), action));
}

export function table(headers, rows) {
  return h('div', { class: 'card table-wrap' },
    h('table', null,
      h('thead', null, h('tr', null, headers.map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', null, rows)));
}
