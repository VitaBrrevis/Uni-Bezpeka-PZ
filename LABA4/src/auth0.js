import fetch from 'node-fetch';
import jwt from 'jsonwebtoken';

const form = (obj) =>
  Object.entries(obj)
    .filter(([_, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

export async function tokenByPasswordRealm({
  domain,
  client_id,
  client_secret,
  username,
  password,
  realm = 'Username-Password-Authentication',
  scope = 'openid profile email offline_access',
  audience = ''
}) {
  const url = `https://${domain}/oauth/token`;
  const body = form({
    grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
    realm,
    username,
    password,
    client_id,
    client_secret,
    scope,
    // leave audience empty to get refresh_token reliably
    audience: audience || undefined
  });
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`ROPC failed: ${res.status} ${JSON.stringify(data)}`);
  return data; // { access_token, id_token, refresh_token, token_type, expires_in }
}

export async function refreshToken({
  domain,
  client_id,
  client_secret,
  refresh_token
}) {
  const url = `https://${domain}/oauth/token`;
  const body = form({
    grant_type: 'refresh_token',
    client_id,
    client_secret,
    refresh_token
  });
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`Refresh failed: ${res.status} ${JSON.stringify(data)}`);
  return data; // { access_token, id_token?, refresh_token? ... }
}

export async function getManagementToken({
  domain,
  client_id,
  client_secret,
  audience
}) {
  const url = `https://${domain}/oauth/token`;
  const body = form({
    grant_type: 'client_credentials',
    client_id,
    client_secret,
    audience
  });
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`Mgmt token failed: ${res.status} ${JSON.stringify(data)}`);
  return data.access_token;
}

export async function createUser({
  domain,
  mgmt_token,
  email,
  password,
  connection = 'Username-Password-Authentication',
  given_name,
  family_name
}) {
  const url = `https://${domain}/api/v2/users`;
  const payload = {
    email,
    password,
    connection,
    given_name,
    family_name
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'authorization': `Bearer ${mgmt_token}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`Create user failed: ${res.status} ${JSON.stringify(data)}`);
  return data;
}

export function decodeIdToken(id_token) {
  try {
    return jwt.decode(id_token) || {};
  } catch {
    return {};
  }
}
