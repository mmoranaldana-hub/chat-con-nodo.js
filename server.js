
const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'chat.db');

// ensure data folder
const fs = require('fs');
if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));

// open sqlite db
const db = new sqlite3.Database(DB_FILE);

// create tables if not exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// session
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.join(__dirname,'data') }),
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// helper: require auth
function requireAuth(req, res, next){
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// auth endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
    stmt.run(username, hash, function(err){
      if (err) return res.status(400).json({ error: 'Username taken' });
      req.session.user = { id: this.lastID, username };
      res.json({ id: this.lastID, username });
    });
    stmt.finalize();
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT id, username, password_hash FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!row) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    req.session.user = { id: row.id, username: row.username };
    res.json({ id: row.id, username: row.username });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) return res.json({ user: req.session.user });
  res.json({ user: null });
});

// messages
app.get('/api/messages', (req, res) => {
  db.all('SELECT id, user_id, username, text, created_at FROM messages ORDER BY id ASC LIMIT 100', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.post('/api/messages', requireAuth, (req, res) => {
  const user = req.session.user;
  const text = req.body.text;
  if (!text) return res.status(400).json({ error: 'No text provided' });
  const stmt = db.prepare('INSERT INTO messages (user_id, username, text) VALUES (?, ?, ?)');
  stmt.run(user.id, user.username, text, function(err){
    if (err) return res.status(500).json({ error: 'DB error' });
    const msg = { id: this.lastID, user_id: user.id, username: user.username, text, created_at: new Date().toISOString() };
    io.emit('message', msg);
    res.json(msg);
  });
  stmt.finalize();
});

// serve index.html for all other routes (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Simple socket connection to notify clients (no authentication required for socket connect)
io.on('connection', (socket) => {
  console.log('socket connected', socket.id);
  socket.on('disconnect', ()=>{
    console.log('socket disconnected', socket.id);
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
