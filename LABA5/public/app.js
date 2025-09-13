const out = document.getElementById('out');
const show = (x) => out.textContent = JSON.stringify(x, null, 2);

const post = async (p, data) => {
  const res = await fetch(p, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(data||{}), credentials:'include' });
  const j = await res.json().catch(() => ({}));
  return {ok:res.ok,status:res.status,body:j};
};

const get = async (p, bearer) => {
  const headers = {};
  if (bearer) headers['authorization'] = `Bearer ${bearer}`;
  const res = await fetch(p, { headers, credentials:'include' });
  const j = await res.json().catch(() => ({}));
  return {ok:res.ok,status:res.status,body:j};
};

document.getElementById('btn-login').onclick = async () => {
  const username = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-pass').value.trim();
  show(await post('/api/login', { username, password }));
};

document.getElementById('btn-signup').onclick = async () => {
  const email = document.getElementById('su-email').value.trim();
  const password = document.getElementById('su-pass').value.trim();
  const given_name = document.getElementById('su-given').value.trim();
  const family_name = document.getElementById('su-family').value.trim();
  show(await post('/api/signup', { email, password, given_name, family_name, connection: 'Username-Password-Authentication' }));
};

document.getElementById('btn-me').onclick = async () => {
  show(await get('/api/me'));
};

document.getElementById('btn-protected').onclick = async () => {
  show(await get('/api/protected'));
};

document.getElementById('btn-verify-id').onclick = async () => {
  show(await get('/api/verify-id'));
};

document.getElementById('btn-verify-access').onclick = async () => {
  const token = document.getElementById('bearer').value.trim();
  show(await get('/api/verify-access', token));
};

document.getElementById('btn-protected-verified').onclick = async () => {
  show(await get('/api/protected-verified'));
};
