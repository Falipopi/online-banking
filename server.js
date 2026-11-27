const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = 'dev-secret-change-me';

// --- AUTH ROUTES ---

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8)
    return res.status(400).json({ error: 'Invalid input (password must be 8+ chars)' });

  const hash = await bcrypt.hash(password, 10);
  try {
    const info = db.prepare(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)'
    ).run(email, hash);

    db.prepare('INSERT INTO accounts (user_id) VALUES (?)').run(info.lastInsertRowid);
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'Email already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
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

app.get('/api/account', auth, (req, res) => {
  const acct = db.prepare('SELECT id, balance_cents FROM accounts WHERE user_id = ?')
    .get(req.user.userId);
  res.json(acct);
});

const transfer = db.transaction((fromUserId, toAccountId, amount) => {
  const from = db.prepare('SELECT * FROM accounts WHERE user_id = ?').get(fromUserId);
  const to = db.prepare('SELECT * FROM accounts WHERE id = ?').get(toAccountId);
  
  if (!to) throw new Error('Destination not found');
  if (from.balance_cents < amount) throw new Error('Insufficient funds');

  db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?')
    .run(amount, from.id);
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?')
    .run(amount, toAccountId);

  db.prepare('INSERT INTO transactions (account_id, type, amount_cents) VALUES (?,?,?)')
    .run(from.id, 'transfer_out', amount);
  db.prepare('INSERT INTO transactions (account_id, type, amount_cents) VALUES (?,?,?)')
    .run(toAccountId, 'transfer_in', amount);
});

app.post('/api/transfer', auth, (req, res) => {
  const { toAccountId, amountCents } = req.body;
  if (!Number.isInteger(amountCents) || amountCents <= 0)
    return res.status(400).json({ error: 'Invalid amount' });

  try {
    transfer(req.user.userId, toAccountId, amountCents);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.listen(3000, () => console.log('Bank running on http://localhost:3000'));