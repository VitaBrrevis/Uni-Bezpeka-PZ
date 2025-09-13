import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { tokenByPasswordRealm, refreshToken, getManagementToken, createUser, decodeIdToken } from './auth0.js';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.AUTH0_DOMAIN;
const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const REALM = process.env.AUTH0_REALM || 'Username-Password-Authentication';
const AUDIENCE = process.env.AUTH0_AUDIENCE || '';

const MGMT_CLIENT_ID = process.env.AUTH0_MGMT_CLIENT_ID;
const MGMT_CLIENT_SECRET = process.env.AUTH0_MGMT_CLIENT_SECRET;
const MGMT_AUDIENCE = process.env.AUTH0_MGMT_AUDIENCE;

const THRESH = Number(process.env.TOKEN_REFRESH_THRESHOLD_SEC || 120);

function setAuthCookies(res, tokens) {
  const now = Math.floor(Date.now() / 1000);
  const expires_at = now + (tokens.expires_in || 3600);
  res.cookie('access_token', tokens.access_token, { httpOnly: true, sameSite: 'lax' });
  if (tokens.id_token) res.cookie('id_token', tokens.id_token, { httpOnly: true, sameSite: 'lax' });
  if (tokens.refresh_token) res.cookie('refresh_token', tokens.refresh_token, { httpOnly: true, sameSite: 'lax' });
  res.cookie('expires_at', String(expires_at), { httpOnly: true, sameSite: 'lax' });
}

async function ensureFreshToken(req, res, next) {
  try {
    const id_token = req.cookies.id_token;
    const refresh_token = req.cookies.refresh_token;
    if (!id_token) return res.status(401).json({ error: 'No id_token cookie' });
    const claims = decodeIdToken(id_token) || {};
    const now = Math.floor(Date.now() / 1000);
    const exp = claims.exp || Number(req.cookies.expires_at || 0);
    if (exp - now <= THRESH) {
      if (!refresh_token) return res.status(401).json({ error: 'Token expiring; no refresh_token available' });
      const refreshed = await refreshToken({
        domain: DOMAIN,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token
      });
      setAuthCookies(res, refreshed);
    }
    next();
  } catch (e) {
    console.error(e);
    res.status(401).json({ error: 'Auto-refresh failed', detail: String(e) });
  }
}

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const tokens = await tokenByPasswordRealm({
      domain: DOMAIN,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      username,
      password,
      realm: REALM,
      audience: AUDIENCE
    });
    setAuthCookies(res, tokens);
    res.json({ ok: true, tokens });
  } catch (e) {
    res.status(401).json({ ok: false, error: String(e) });
  }
});

app.post('/api/refresh', async (req, res) => {
  try {
    const refresh_token = req.body.refresh_token || req.cookies.refresh_token;
    if (!refresh_token) return res.status(400).json({ error: 'No refresh_token provided' });
    const tokens = await refreshToken({
      domain: DOMAIN,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token
    });
    setAuthCookies(res, tokens);
    res.json({ ok: true, tokens });
  } catch (e) {
    res.status(401).json({ ok: false, error: String(e) });
  }
});

app.get('/api/me', (req, res) => {
  const id_token = req.cookies.id_token;
  if (!id_token) return res.status(401).json({ error: 'No id_token' });
  const claims = decodeIdToken(id_token) || {};
  res.json({ ok: true, claims });
});

app.get('/api/protected', ensureFreshToken, (req, res) => {
  const id_token = req.cookies.id_token;
  const claims = decodeIdToken(id_token) || {};
  res.json({ ok: true, sub: claims.sub, message: 'You are in a protected route with fresh token.' });
});

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, given_name, family_name, connection } = req.body;
    const mgmt = await getManagementToken({
      domain: DOMAIN,
      client_id: MGMT_CLIENT_ID,
      client_secret: MGMT_CLIENT_SECRET,
      audience: MGMT_AUDIENCE
    });
    const created = await createUser({
      domain: DOMAIN,
      mgmt_token: mgmt,
      email,
      password,
      given_name,
      family_name,
      connection: connection || REALM
    });
    res.status(201).json({ ok: true, user: created });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`Auth0 token_auth sample running on http://localhost:${PORT}`);
});
