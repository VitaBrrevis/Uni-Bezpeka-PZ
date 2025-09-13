const out = document.getElementById('out');

const show = (obj) => {
  out.textContent = JSON.stringify(obj, null, 2);
};

const post = async (path, data) => {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(data || {}),
    credentials: 'include'
  });
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body: json };
};

const get = async (path) => {
  const res = await fetch(path, { credentials: 'include' });
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body: json };
};

document.getElementById('btn-login').onclick = async () => {
  const username = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-pass').value;
  const r = await post('/api/login', { username, password });
  show(r);
};

document.getElementById('btn-signup').onclick = async () => {
  const email = document.getElementById('su-email').value.trim();
  const password = document.getElementById('su-pass').value;
  const given_name = document.getElementById('su-given').value.trim();
  const family_name = document.getElementById('su-family').value.trim();
  const r = await post('/api/signup', { email, password, given_name, family_name, connection: 'Username-Password-Authentication' });
  show(r);
};

document.getElementById('btn-me').onclick = async () => {
  const r = await get('/api/me');
  show(r);
};

document.getElementById('btn-protected').onclick = async () => {
  const r = await get('/api/protected');
  show(r);
};

document.getElementById('btn-refresh').onclick = async () => {
  const refresh_token = document.getElementById('rf-token').value.trim();
  const payload = refresh_token ? { refresh_token } : {};
  const r = await post('/api/refresh', payload);
  show(r);
};
