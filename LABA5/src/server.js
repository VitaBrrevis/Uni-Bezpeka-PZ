import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { tokenByPasswordRealm, refreshToken, getManagementToken, createUser, decodeIdToken } from './auth0.js';
import { verifyIdToken, verifyAccessToken } from './verify.js';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// Serve UI
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pubPath = path.join(__dirname, '..', 'public');
app.use(express.static(pubPath));

const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.AUTH0_DOMAIN;
const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const REALM = process.env.AUTH0_REALM || 'Username-Password-Authentication';
const AUDIENCE = process.env.AUTH0_AUDIENCE || '';

const ISSUER = (process.env.AUTH0_ISSUER || `https://${DOMAIN}/`).replace(/\/?$/, '/');
const JWKS_URI = process.env.AUTH0_JWKS_URI || `https://${DOMAIN}/.well-known/jwks.json`;
const PEM_URL = process.env.AUTH0_PEM_URL || '';

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

// ====== API ======
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
  res.json({ ok: true, claims: decodeIdToken(id_token) || {} });
});

app.get('/api/protected', ensureFreshToken, (req, res) => {
  const id_token = req.cookies.id_token;
  res.json({ ok: true, message: 'Protected route (auto-refresh checked).', sub: decodeIdToken(id_token)?.sub });
});

// --- ПЕРЕВІРКА ПІДПИСУ ---
function bearerFrom(req, cookieName = '') {
  const auth = req.headers['authorization'] || '';
  if (auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  if (cookieName && req.cookies[cookieName]) return req.cookies[cookieName];
  return '';
}

app.get('/api/verify-id', async (req, res) => {
  try {
    const token = bearerFrom(req, 'id_token');
    if (!token) return res.status(400).json({ error: 'ID token not provided (cookie or Authorization: Bearer)' });
    const result = await verifyIdToken({ token, issuer: ISSUER, clientId: CLIENT_ID, jwksUri: JWKS_URI, pemUrl: PEM_URL });
    res.json({ ok: true, valid: result.valid, method: result.method, decoded: result.decoded });
  } catch (e) {
    res.status(401).json({ ok: false, valid: false, error: String(e) });
  }
});

app.get('/api/verify-access', async (req, res) => {
  try {
    const token = bearerFrom(req, 'access_token');
    if (!token) return res.status(400).json({ error: 'Access token not provided (cookie or Authorization: Bearer)' });
    if (!AUDIENCE) return res.status(400).json({ error: 'AUTH0_AUDIENCE is empty; access_token may be opaque. Set audience and login again.' });
    const result = await verifyAccessToken({ token, issuer: ISSUER, audience: AUDIENCE, jwksUri: JWKS_URI, pemUrl: PEM_URL });
    res.json({ ok: true, valid: result.valid, method: result.method, decoded: result.decoded });
  } catch (e) {
    res.status(401).json({ ok: false, valid: false, error: String(e) });
  }
});

app.get('/api/protected-verified', async (req, res) => {
  try {
    const token = bearerFrom(req, 'id_token');
    if (!token) return res.status(401).json({ error: 'No id_token' });
    await verifyIdToken({ token, issuer: ISSUER, clientId: CLIENT_ID, jwksUri: JWKS_URI, pemUrl: PEM_URL });
    res.json({ ok: true, message: 'You have a valid, signed ID token.' });
  } catch (e) {
    res.status(401).json({ ok: false, error: 'Invalid token signature or claims', detail: String(e) });
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, given_name, family_name, connection } = req.body;
    const mgmt = await getManagementToken({ domain: DOMAIN, client_id: MGMT_CLIENT_ID, client_secret: MGMT_CLIENT_SECRET, audience: MGMT_AUDIENCE });
    const created = await createUser({ domain: DOMAIN, mgmt_token: mgmt, email, password, given_name, family_name, connection: connection || REALM });
    res.status(201).json({ ok: true, user: created });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`Lab4 app running: http://localhost:${PORT}`);
});
