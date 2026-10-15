// Enrollment and sign-in confirmation pages for trusted devices. The browser
// asks the platform authenticator (Windows Hello, Touch ID) to create or use
// a key held in the device's security chip.

const root = document.getElementById('device');
const go = document.getElementById('go');
const errorBox = document.getElementById('error');
const doneBox = document.getElementById('done');

const b64u = {
  dec(s) {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
    return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
  },
  enc(buf) {
    let s = '';
    for (const byte of new Uint8Array(buf)) s += String.fromCharCode(byte);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {
    // no body
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function creationOptions({ publicKey: pk }) {
  pk.challenge = b64u.dec(pk.challenge);
  pk.user.id = b64u.dec(pk.user.id);
  for (const c of pk.excludeCredentials || []) c.id = b64u.dec(c.id);
  return { publicKey: pk };
}

function requestOptions({ publicKey: pk }) {
  pk.challenge = b64u.dec(pk.challenge);
  for (const c of pk.allowCredentials || []) c.id = b64u.dec(c.id);
  return { publicKey: pk };
}

function credentialJSON(cred) {
  const r = cred.response;
  const response = { clientDataJSON: b64u.enc(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = b64u.enc(r.attestationObject);
    if (r.getTransports) response.transports = r.getTransports();
  } else {
    response.authenticatorData = b64u.enc(r.authenticatorData);
    response.signature = b64u.enc(r.signature);
    if (r.userHandle) response.userHandle = b64u.enc(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: b64u.enc(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response,
  };
}

function explain(err) {
  switch (err && err.name) {
    case 'NotAllowedError':
      return 'The request was cancelled or timed out. Try again, and confirm with your PIN, fingerprint or face.';
    case 'InvalidStateError':
      return 'This device is already enrolled for this user.';
    case 'NotSupportedError':
      return 'This browser or device does not support the required security key type.';
    case 'SecurityError':
      return 'The browser refused the request for security reasons. Make sure you opened the link exactly as sent.';
    default:
      return (err && err.message) || String(err);
  }
}

function showError(err) {
  errorBox.textContent = explain(err);
  errorBox.hidden = false;
}

async function enroll() {
  const { publicKey } = creationOptions(await post('/device/enroll/begin', { code: root.dataset.code }));
  const cred = await navigator.credentials.create({ publicKey });
  const out = await post('/device/enroll/finish', credentialJSON(cred));
  doneBox.textContent = `Done. ${out.device} is now a trusted device for ${out.user}. You can close this page.`;
  doneBox.hidden = false;
  go.hidden = true;
}

async function verify() {
  const opts = await post('/auth/device/begin', { app: root.dataset.app, rd: root.dataset.rd });
  const cred = await navigator.credentials.get(requestOptions(opts));
  const out = await post('/auth/device/finish', credentialJSON(cred));
  location.assign(out.next);
}

async function start() {
  if (!go) return; // error page
  if (!window.PublicKeyCredential || !navigator.credentials) {
    showError(new Error('This browser does not support device security keys. Use an up-to-date Chrome, Edge, Safari or Firefox.'));
    go.disabled = true;
    return;
  }
  if (root.dataset.mode === 'enroll' && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    try {
      if (!(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) {
        showError(new Error('This device has no built-in authenticator set up. Turn on Windows Hello (or Touch ID on a Mac), then reload this page.'));
      }
    } catch {
      // unknown: let the attempt decide
    }
  }
  go.addEventListener('click', async () => {
    errorBox.hidden = true;
    go.disabled = true;
    try {
      await (root.dataset.mode === 'enroll' ? enroll() : verify());
    } catch (err) {
      showError(err);
    } finally {
      go.disabled = false;
    }
  });
  go.focus();
}

start();
