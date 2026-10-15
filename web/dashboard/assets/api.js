// Client for the control plane admin API. The session cookie authenticates;
// every state-changing call also sends the session's CSRF token.

let csrfToken = '';

export function setCSRF(token) {
  csrfToken = token || '';
}

export class APIError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function api(method, path, body) {
  const opts = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (method !== 'GET') opts.headers['X-CSRF-Token'] = csrfToken;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch('/api/v1' + path, opts);
  if (res.status === 204) return null;
  let data = null;
  try {
    data = await res.json();
  } catch {
    // non-JSON body
  }
  if (!res.ok) {
    const err = new APIError(res.status, (data && data.error) || `Request failed (${res.status})`);
    if (res.status === 401) window.dispatchEvent(new CustomEvent('vexel:signed-out'));
    throw err;
  }
  return data;
}

export const get = (path) => api('GET', path);
export const post = (path, body) => api('POST', path, body ?? {});
export const put = (path, body) => api('PUT', path, body);
export const del = (path) => api('DELETE', path);
