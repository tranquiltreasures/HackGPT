/******************************************************************
 * server.js – HackGPT authentication + chat proxy (minimal demo)
 ******************************************************************/
require('dotenv').config();
const express     = require('express');
const bodyParser  = require('body-parser');
const cors        = require('cors');
const bcrypt      = require('bcrypt');
const jwt         = require('jsonwebtoken');
const sqlite3     = require('sqlite3').verbose();
const path        = require('path');
const app         = express();
const PORT        = process.env.PORT || 3000;

/* ------------- STATIC FILES (your html / css / js) -------------- */
app.use(express.static(path.join(__dirname, 'public')));

/* ------------------------ MIDDLEWARE ---------------------------- */
app.use(cors());
app.use(bodyParser.json());

/* ------------------------- DATABASE ----------------------------- */
const db = new sqlite3.Database('./hackgpt.db');
db.serialize(() => {
  // users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            pass_hash     TEXT NOT NULL,
            token_used    TEXT,
            access_until  INTEGER        -- millis since epoch
          )`);
});

/* -------------------- ACCESS‑TOKEN REGISTRY --------------------- */
/*  You handed us *absolute expiry* timestamps, so just keep them in memory
    (for small projects) or move to a proper table later.              */
const validKeys = {
  "DEMO123":  Date.now() + (7  * 24 * 60 * 60 * 1000), // 7 days
  "TEST456":  Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
  "TRIAL789": Date.now() + (3  * 24 * 60 * 60 * 1000)  // 3 days
};

/* -------------------- 1.  VALIDATE‑TOKEN ------------------------ */
app.post('/validate-token', (req, res) => {
  const { token } = req.body;
  const expiry = validKeys[token];

  if (!expiry) return res.json({ valid: false });

  // Is the key expired?
  if (Date.now() > expiry) return res.json({ valid: false });

  // How many days are left?
  const daysLeft = Math.ceil((expiry - Date.now()) / (24*60*60*1000));
  return res.json({ valid: true, days: daysLeft });
});

/* -------------------- 2.  REGISTER USER ------------------------- */
app.post('/register', async (req, res) => {
  const { username, password, token } = req.body;

  // Re‑check token (never trust client)
  const expiry = validKeys[token];
  if (!expiry || Date.now() > expiry) {
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }

  // Hash password
  const pass_hash = await bcrypt.hash(password, 12);

  // Store user
  db.run(`INSERT INTO users (username, pass_hash, token_used, access_until)
          VALUES (?,?,?,?)`,
          [username, pass_hash, token, expiry],
          function (err) {
            if (err) {
              if (err.code === 'SQLITE_CONSTRAINT') {
                return res.status(409).json({ error: 'Username already taken.' });
              }
              return res.status(500).json({ error: 'DB error.' });
            }
            // Remove the token from validKeys so it can’t be used again (one‑time)
            delete validKeys[token];

            // Create a session JWT
            const sessionToken = jwt.sign(
              { uid: this.lastID, exp: Math.floor(expiry / 1000) },
              process.env.JWT_SECRET
            );
            res.json({ ok: true, sessionToken });
          });
});

/* -------------------- 3.  LOGIN USER ---------------------------- */
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username=?`, [username], async (err, row) => {
    if (err || !row) return res.status(401).json({ error: 'Invalid credentials.' });

    const pwOk = await bcrypt.compare(password, row.pass_hash);
    if (!pwOk) return res.status(401).json({ error: 'Invalid credentials.' });

    if (Date.now() > row.access_until) {
      return res.status(403).json({ error: 'Subscription expired.' });
    }

    const sessionToken = jwt.sign(
      { uid: row.id, exp: Math.floor(row.access_until / 1000) },
      process.env.JWT_SECRET
    );
    res.json({ ok: true, sessionToken });
  });
});

/* -------------------- 4.  PROTECTED CHAT ------------------------ */
app.post('/chat', authenticate, async (req, res) => {
  // forward to Nano‑GPT API (simplified, no streaming here)
  try {
    const nanoRes = await fetch(`${process.env.BASE_URL}/chat/completions`, {
      method : 'POST',
      headers: {
        'Authorization' : `Bearer ${process.env.API_KEY}`,
        'Content-Type'  : 'application/json'
      },
      body: JSON.stringify({
        model   : process.env.MODEL,
        messages: req.body.messages
      })
    });
    const data = await nanoRes.json();
    res.json({ reply: data.choices?.[0]?.message?.content || '…' });
  } catch (e) {
    res.status(502).json({ error: 'Upstream API error.' });
  }
});

/* ---------------- AUTH MIDDLEWARE (JWT) ------------------------- */
function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.split(' ')[1];
  if (!token) return res.status(401).end();

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.uid;
    next();
  } catch (_) {
    res.status(401).end();
  }
}

/* ------------------------- START ------------------------------- */
app.listen(PORT, () => console.log(`HackGPT backend running on :${PORT}`));