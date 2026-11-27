const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { sql, initDb } = require('./db');

const app = express();
app.use(express.json());
const path = require('path');

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize DB on cold start
initDb().catch(console.error);

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// --- AUTH ROUTES ---
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8)
    return res.status(400).json({ error: 'Invalid input' });

  const hash = await bcrypt.hash(password, 10);
  try {
    const userRes = await sql`INSERT INTO users (email, password_hash) VALUES (${email}, ${hash}) RETURNING id`;
    await sql`INSERT INTO accounts (user_id) VALUES (${userRes.rows[0].id})`;
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'Email already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const userRes = await sql`SELECT * FROM users WHERE email = ${email}`;
  const user = userRes.rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// --- MIDDLEWARE ---
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// --- BANKING ROUTES ---
app.get('/api/account', auth, async (req, res) => {
  const acctRes = await sql`SELECT id, balance_cents FROM accounts WHERE user_id = ${req.user.userId}`;
  res.json(acctRes.rows[0]);
});

app.post('/api/transfer', auth, async (req, res) => {
  const { toAccountId, amountCents } = req.body;
  if (!Number.isInteger(amountCents) || amountCents <= 0)
    return res.status(400).json({ error: 'Invalid amount' });

  try {
    const fromRes = await sql`SELECT * FROM accounts WHERE user_id = ${req.user.userId}`;
    const from = fromRes.rows[0];
    
    if (from.balance_cents < amountCents) throw new Error('Insufficient funds');

    await sql`UPDATE accounts SET balance_cents = balance_cents - ${amountCents} WHERE id = ${from.id}`;
    await sql`UPDATE accounts SET balance_cents = balance_cents + ${amountCents} WHERE id = ${toAccountId}`;
    
    await sql`INSERT INTO transactions (account_id, type, amount_cents) VALUES (${from.id}, 'transfer_out', ${amountCents})`;
    await sql`INSERT INTO transactions (account_id, type, amount_cents) VALUES (${toAccountId}, 'transfer_in', ${amountCents})`;

    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.post('/api/deposit', auth, async (req, res) => {
  const { amountCents } = req.body;
  if (!Number.isInteger(amountCents) || amountCents <= 0)
    return res.status(400).json({ error: 'Invalid amount' });

  try {
    await sql`UPDATE accounts SET balance_cents = balance_cents + ${amountCents} WHERE user_id = ${req.user.userId}`;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
// Vercel requires this export, no app.listen()
module.exports = app;