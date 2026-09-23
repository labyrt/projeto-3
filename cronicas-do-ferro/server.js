'use strict';

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const COOKIE = 'cdf_session';

if (!DATABASE_URL) throw new Error('DATABASE_URL ausente');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET ausente ou curto');

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.DB_SSL === 'disable' ? false : { rejectUnauthorized: false }, max: 8 });
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      manifestSrc: ["'self'"],
      workerSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '128kb' }));
app.use(cookieParser());

const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 25, standardHeaders: 'draft-8', legacyHeaders: false });
const saveLimiter = rateLimit({ windowMs: 60 * 1000, limit: 90, standardHeaders: 'draft-8', legacyHeaders: false });

function normalizeUsername(value) {
  const username = String(value || '').trim();
  if (!/^[A-Za-z0-9_.-]{3,20}$/.test(username)) return null;
  return username;
}
function validatePassword(value) {
  return typeof value === 'string' && value.length >= 8 && value.length <= 72;
}
function signSession(user) {
  return jwt.sign({ uid: user.id, username: user.username, nonce: crypto.randomBytes(6).toString('hex') }, SESSION_SECRET, { expiresIn: '30d', issuer: 'cronicas-do-ferro' });
}
function setSession(res, user) {
  res.cookie(COOKIE, signSession(user), { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000, path: '/' });
}
function clearSession(res) {
  res.clearCookie(COOKIE, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
}
function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE];
  if (!token) return res.status(401).json({ error: 'Entre na conta para usar o save na nuvem.' });
  try {
    const payload = jwt.verify(token, SESSION_SECRET, { issuer: 'cronicas-do-ferro' });
    req.user = { id: Number(payload.uid), username: payload.username };
    next();
  } catch {
    clearSession(res);
    return res.status(401).json({ error: 'Sessão expirada. Entre novamente.' });
  }
}
function publicUser(row) { return { id: Number(row.id), username: row.username }; }
function validSave(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
  if (!data.player || typeof data.player !== 'object') return false;
  if (!['hunter', 'guardian', 'occult'].includes(data.player.classId)) return false;
  if (!['village', 'forest', 'dungeon1', 'dungeon2'].includes(data.player.area)) return false;
  if (!Number.isFinite(Number(data.savedAt))) return false;
  return JSON.stringify(data).length <= 100000;
}

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(20) NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uidx ON users ((LOWER(username)));
    CREATE TABLE IF NOT EXISTS game_saves (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, version: 3 }); }
  catch { res.status(503).json({ ok: false }); }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = req.body?.password;
  if (!username) return res.status(400).json({ error: 'Nome inválido. Use 3–20 caracteres: letras, números, ponto, _ ou -.' });
  if (!validatePassword(password)) return res.status(400).json({ error: 'A senha deve ter entre 8 e 72 caracteres.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const q = await pool.query('INSERT INTO users(username, password_hash) VALUES ($1, $2) RETURNING id, username', [username, hash]);
    const user = publicUser(q.rows[0]);
    setSession(res, user);
    return res.status(201).json({ user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Esse nome de caçador já está em uso.' });
    console.error('register_error', e.message);
    return res.status(500).json({ error: 'Não foi possível criar a conta agora.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = req.body?.password;
  if (!username || !validatePassword(password)) return res.status(401).json({ error: 'Nome ou senha incorretos.' });
  try {
    const q = await pool.query('SELECT id, username, password_hash FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1', [username]);
    const row = q.rows[0];
    if (!row || !(await bcrypt.compare(password, row.password_hash))) return res.status(401).json({ error: 'Nome ou senha incorretos.' });
    const user = publicUser(row);
    setSession(res, user);
    return res.json({ user });
  } catch (e) {
    console.error('login_error', e.message);
    return res.status(500).json({ error: 'Não foi possível entrar agora.' });
  }
});

app.post('/api/auth/logout', (_req, res) => { clearSession(res); res.json({ ok: true }); });
app.get('/api/auth/me', requireAuth, async (req, res) => res.json({ user: req.user }));

app.get('/api/save', requireAuth, async (req, res) => {
  try {
    const q = await pool.query('SELECT data, updated_at FROM game_saves WHERE user_id = $1', [req.user.id]);
    if (!q.rows[0]) return res.json({ data: null, updatedAt: null });
    return res.json({ data: q.rows[0].data, updatedAt: q.rows[0].updated_at });
  } catch (e) {
    console.error('save_read_error', e.message);
    return res.status(500).json({ error: 'Não foi possível carregar o save na nuvem.' });
  }
});

app.put('/api/save', requireAuth, saveLimiter, async (req, res) => {
  const data = req.body?.data;
  if (!validSave(data)) return res.status(400).json({ error: 'Save inválido.' });
  try {
    await pool.query(`
      INSERT INTO game_saves(user_id, data, updated_at) VALUES ($1, $2::jsonb, NOW())
      ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
      WHERE COALESCE((game_saves.data->>'savedAt')::bigint, 0) <= COALESCE((EXCLUDED.data->>'savedAt')::bigint, 0)
    `, [req.user.id, JSON.stringify(data)]);
    return res.json({ ok: true, savedAt: data.savedAt });
  } catch (e) {
    console.error('save_write_error', e.message);
    return res.status(500).json({ error: 'Não foi possível salvar na nuvem.' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { etag: true, maxAge: '1h', extensions: ['html'] }));

migrate().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`Crônicas do Ferro online na porta ${PORT}`));
}).catch(err => {
  console.error('migration_error', err);
  process.exit(1);
});
