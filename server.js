// server.js (versión completa y corregida — usa sqlite3)
// Requerimientos:
//   npm install sqlite3
// Colocar este archivo en la raíz del proyecto (junto a public/).
// Mantiene compatibilidad con tu index.html y sockets.

const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const util = require('util');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// SQLite DB
const DB_PATH = path.join(DATA_DIR, 'chat.db');
const db = new sqlite3.Database(DB_PATH);
db.runAsync = util.promisify(db.run.bind(db));
db.getAsync = util.promisify(db.get.bind(db));
db.allAsync = util.promisify(db.all.bind(db));

// Initialize schema
(async function initDb() {
  // users table
  await db.runAsync(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    avatar TEXT,
    description TEXT,
    online INTEGER DEFAULT 0
  )`);
  // contacts (bidirectional stored as pairs)
  await db.runAsync(`CREATE TABLE IF NOT EXISTS contacts (
    user_id INTEGER,
    contact_id INTEGER,
    UNIQUE(user_id, contact_id)
  )`);
  // friend requests
  await db.runAsync(`CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER,
    to_id INTEGER,
    created_at TEXT
  )`);
  // global messages
  await db.runAsync(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    text TEXT,
    created_at TEXT
  )`);
  // private messages
  await db.runAsync(`CREATE TABLE IF NOT EXISTS private_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER,
    to_id INTEGER,
    text TEXT,
    created_at TEXT,
    read_by TEXT
  )`);
  // groups
  await db.runAsync(`CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    created_by INTEGER
  )`);
  // group members
  await db.runAsync(`CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER,
    user_id INTEGER,
    UNIQUE(group_id, user_id)
  )`);
  // group messages
  await db.runAsync(`CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    from_id INTEGER,
    text TEXT,
    created_at TEXT,
    read_by TEXT
  )`);
})().catch(err => {
  console.error('DB init error', err);
});

// middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

async function getUserBySession(req) {
  if (!req.session || !req.session.user) return null;
  const id = req.session.user.id;
  const user = await db.getAsync('SELECT id,username,avatar,description,online FROM users WHERE id = ?', [id]);
  return user || null;
}

// ---------- AUTH ----------
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing username/password' });

    const existing = await db.getAsync('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return res.status(400).json({ error: 'Username already exists' });

    const hash = await bcrypt.hash(password, 10);
    const result = await db.runAsync('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
    // get last id
    const userId = result.lastID;
    req.session.user = { id: userId, username };
    res.json(req.session.user);
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing username/password' });

    const user = await db.getAsync('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    req.session.user = { id: user.id, username: user.username };
    res.json(req.session.user);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.json({ user: null });
    const id = req.session.user.id;
    const user = await db.getAsync('SELECT id,username,avatar,description,online FROM users WHERE id = ?', [id]);
    if (!user) return res.json({ user: null });
    res.json({ user: { id: user.id, username: user.username, avatar: user.avatar, description: user.description, online: !!user.online }});
  } catch (err) {
    console.error('Get /me error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/me/profile', requireAuth, async (req, res) => {
  try {
    const { description, avatar } = req.body || {};
    const user = await getUserBySession(req);
    if (!user) return res.status(400).json({ error: 'User not found' });

    await db.runAsync('UPDATE users SET description = COALESCE(?, description), avatar = COALESCE(?, avatar) WHERE id = ?', [description === undefined ? null : description, avatar === undefined ? null : avatar, user.id]);

    const updated = await db.getAsync('SELECT id,username,avatar,description FROM users WHERE id = ?', [user.id]);
    res.json({ ok: true, avatar: updated.avatar, description: updated.description });
  } catch (err) {
    console.error('Profile update error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- FRIEND REQUESTS ----------
app.post('/api/friend/request', requireAuth, async (req, res) => {
  try {
    const { to } = req.body || {};
    if (!to) return res.status(400).json({ error: "Missing 'to' username" });

    const me = await getUserBySession(req);
    if (!me) return res.status(400).json({ error: 'Authenticated user not found' });

    const target = await db.getAsync('SELECT id,username FROM users WHERE username = ?', [to]);
    if (!target) return res.status(400).json({ error: 'User not found' });
    if (target.id === me.id) return res.status(400).json({ error: 'Cannot add yourself' });

    // check existing contact
    const contactExists = await db.getAsync('SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?', [me.id, target.id]);
    if (contactExists) return res.status(400).json({ error: 'Already contact' });

    // check existing request
    const reqExists = await db.getAsync('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?', [me.id, target.id]);
    if (reqExists) return res.status(400).json({ error: 'Request already sent' });

    await db.runAsync('INSERT INTO friend_requests (from_id, to_id, created_at) VALUES (?, ?, ?)', [me.id, target.id, new Date().toISOString()]);

    io.emit('friend_request', { fromId: me.id, fromName: me.username, toId: target.id });
    res.json({ ok: true });
  } catch (err) {
    console.error('Friend request error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/friend/requests', requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    if (!me) return res.status(400).json([]);
    const rows = await db.allAsync('SELECT fr.id,fr.from_id,fr.to_id,fr.created_at,u.username as fromName FROM friend_requests fr JOIN users u ON u.id = fr.from_id WHERE fr.to_id = ?', [me.id]);
    res.json(rows.map(r => ({ id: r.id, from: r.from_id, fromName: r.fromName, created_at: r.created_at })));
  } catch (err) {
    console.error('Get friend requests error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/friend/accept', requireAuth, async (req, res) => {
  try {
    const { requestId } = req.body || {};
    if (!requestId) return res.status(400).json({ error: 'Missing requestId' });

    const reqRow = await db.getAsync('SELECT * FROM friend_requests WHERE id = ?', [requestId]);
    if (!reqRow) return res.status(400).json({ error: 'Request not found' });

    // ensure the acceptor is the 'to' user
    if (reqRow.to_id !== req.session.user.id) return res.status(403).json({ error: 'Not authorized' });

    // add contacts both ways
    const a = reqRow.from_id;
    const b = reqRow.to_id;
    await db.runAsync('INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)', [a, b]);
    await db.runAsync('INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)', [b, a]);

    // remove friend request
    await db.runAsync('DELETE FROM friend_requests WHERE id = ?', [requestId]);

    io.emit('friend_accepted', { from: a, to: b });
    res.json({ ok: true });
  } catch (err) {
    console.error('Friend accept error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- QUICK ADD CONTACT (direct add without request) ----------
app.post('/api/add-contact', requireAuth, async (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: 'Missing username' });

    const me = await getUserBySession(req);
    if (!me) return res.status(400).json({ error: 'Authenticated user not found' });

    const other = await db.getAsync('SELECT id,username FROM users WHERE username = ?', [username]);
    if (!other) return res.status(400).json({ error: 'User not found' });
    if (other.id === me.id) return res.status(400).json({ error: 'Cannot add yourself' });

    await db.runAsync('INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)', [me.id, other.id]);
    await db.runAsync('INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)', [other.id, me.id]);

    io.emit('contact_added', { by: me.id, contact: { id: other.id, username: other.username } });
    res.json({ ok: true });
  } catch (err) {
    console.error('Add contact error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/contacts', requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    if (!me) return res.status(400).json([]);
    const rows = await db.allAsync('SELECT u.id,u.username,u.avatar,u.description,u.online FROM users u JOIN contacts c ON c.contact_id = u.id WHERE c.user_id = ?', [me.id]);
    res.json(rows.map(r => ({ id: r.id, username: r.username, avatar: r.avatar, description: r.description, online: !!r.online })));
  } catch (err) {
    console.error('Get contacts error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- GLOBAL CHAT ----------
app.get('/api/messages', async (req, res) => {
  try {
    const msgs = await db.allAsync('SELECT id,user_id,username,text,created_at FROM messages ORDER BY id DESC LIMIT 200');
    res.json(msgs.reverse()); // return in chronological order
  } catch (err) {
    console.error('Get messages error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text) return res.status(400).json({ error: 'Missing text' });
    const me = await getUserBySession(req);
    const now = new Date().toISOString();
    await db.runAsync('INSERT INTO messages (user_id, username, text, created_at) VALUES (?, ?, ?, ?)', [me.id, me.username, text, now]);
    const msg = { id: this ? this.lastID : Date.now(), user_id: me.id, username: me.username, text, created_at: now };
    // fetch last inserted id more robustly:
    const last = await db.getAsync('SELECT id, user_id, username, text, created_at FROM messages ORDER BY id DESC LIMIT 1');
    io.emit('message', last);
    res.json(last);
  } catch (err) {
    console.error('Post global message error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- PRIVATE MESSAGES ----------
app.post('/api/private/send', requireAuth, async (req, res) => {
  try {
    const { to, text } = req.body || {};
    if (!to || !text) return res.status(400).json({ error: 'Missing to/text' });
    const me = await getUserBySession(req);
    const toId = parseInt(to);
    const now = new Date().toISOString();
    const read_by = JSON.stringify([me.id]); // sender read
    await db.runAsync('INSERT INTO private_messages (from_id, to_id, text, created_at, read_by) VALUES (?, ?, ?, ?, ?)', [me.id, toId, text, now, read_by]);
    const last = await db.getAsync('SELECT * FROM private_messages ORDER BY id DESC LIMIT 1');
    // emit to rooms (client joins pm-{me}-{other} etc.)
    io.to(`pm-${me.id}-${toId}`).emit('private_message', last);
    io.to(`pm-${toId}-${me.id}`).emit('private_message', last);
    res.json(last);
  } catch (err) {
    console.error('Private send error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/private/:withId', requireAuth, async (req, res) => {
  try {
    const withId = parseInt(req.params.withId);
    const my = await getUserBySession(req);
    // fetch conversation
    const rows = await db.allAsync('SELECT * FROM private_messages WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY id ASC', [my.id, withId, withId, my.id]);
    // mark read_by for messages where to_id == me
    let changed = false;
    for (const r of rows) {
      let read = [];
      if (r.read_by) {
        try { read = JSON.parse(r.read_by); } catch(e) { read = []; }
      }
      if (!read.includes(my.id)) {
        read.push(my.id);
        await db.runAsync('UPDATE private_messages SET read_by = ? WHERE id = ?', [JSON.stringify(read), r.id]);
        changed = true;
      }
    }
    res.json(rows);
  } catch (err) {
    console.error('Get private messages error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/private/mark-read', requireAuth, async (req, res) => {
  try {
    const { withId } = req.body || {};
    if (!withId) return res.status(400).json({ error: 'Missing withId' });
    const my = await getUserBySession(req);
    const rows = await db.allAsync('SELECT * FROM private_messages WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)', [my.id, withId, withId, my.id]);
    for (const r of rows) {
      let read = [];
      if (r.read_by) {
        try { read = JSON.parse(r.read_by); } catch(e){ read = []; }
      }
      if (!read.includes(my.id)) {
        read.push(my.id);
        await db.runAsync('UPDATE private_messages SET read_by = ? WHERE id = ?', [JSON.stringify(read), r.id]);
      }
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Mark read error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- GROUPS ----------
app.post('/api/groups/create', requireAuth, async (req, res) => {
  try {
    const { name, members } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Missing group name' });
    const me = await getUserBySession(req);
    const result = await db.runAsync('INSERT INTO groups (name, created_by) VALUES (?, ?)', [name, me.id]);
    const groupId = result.lastID;
    // add creator as member
    await db.runAsync('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', [groupId, me.id]);
    // add other members if provided
    if (Array.isArray(members)) {
      for (const m of members.map(Number)) {
        await db.runAsync('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', [groupId, m]);
      }
    }
    const group = await db.getAsync('SELECT id, name, created_by FROM groups WHERE id = ?', [groupId]);
    // return members count
    const mems = await db.allAsync('SELECT user_id FROM group_members WHERE group_id = ?', [groupId]);
    group.members = mems.map(r => r.user_id);
    io.emit('group_created', group);
    res.json(group);
  } catch (err) {
    console.error('Create group error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/groups/add-member', requireAuth, async (req, res) => {
  try {
    const { group_id, username } = req.body || {};
    if (!group_id || !username) return res.status(400).json({ error: 'Missing group_id/username' });
    const g = await db.getAsync('SELECT id FROM groups WHERE id = ?', [group_id]);
    if (!g) return res.status(400).json({ error: 'Group not found' });
    const userToAdd = await db.getAsync('SELECT id, username FROM users WHERE username = ?', [username]);
    if (!userToAdd) return res.status(400).json({ error: 'User not found' });
    // check membership of requester
    const me = await getUserBySession(req);
    const isMember = await db.getAsync('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [group_id, me.id]);
    if (!isMember) return res.status(403).json({ error: 'Not a member' });
    await db.runAsync('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', [group_id, userToAdd.id]);
    io.to(`group-${group_id}`).emit('group_member_added', { group_id: parseInt(group_id), user: { id: userToAdd.id, username: userToAdd.username } });
    res.json({ ok: true, group_id: group_id });
  } catch (err) {
    console.error('Add member error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/groups', requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    const rows = await db.allAsync('SELECT g.id,g.name, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) AS member_count FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ?', [me.id]);
    const groups = rows.map(r => ({ id: r.id, name: r.name, members: r.member_count }));
    res.json(groups);
  } catch (err) {
    console.error('Get groups error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/groups/send', requireAuth, async (req, res) => {
  try {
    const { group_id, text } = req.body || {};
    if (!group_id || !text) return res.status(400).json({ error: 'Missing group_id/text' });
    const me = await getUserBySession(req);
    const now = new Date().toISOString();
    await db.runAsync('INSERT INTO group_messages (group_id, from_id, text, created_at, read_by) VALUES (?, ?, ?, ?, ?)', [group_id, me.id, text, now, JSON.stringify([me.id])]);
    const last = await db.getAsync('SELECT * FROM group_messages WHERE id = (SELECT MAX(id) FROM group_messages)');
    io.to(`group-${group_id}`).emit('group_message', last);
    res.json(last);
  } catch (err) {
    console.error('Group send error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/groups/messages/:id', requireAuth, async (req, res) => {
  try {
    const gid = parseInt(req.params.id);
    const me = await getUserBySession(req);
    const rows = await db.allAsync('SELECT * FROM group_messages WHERE group_id = ? ORDER BY id ASC', [gid]);
    // mark read_by for user
    for (const r of rows) {
      let read = [];
      if (r.read_by) {
        try { read = JSON.parse(r.read_by); } catch(e){ read = []; }
      }
      if (!read.includes(me.id)) {
        read.push(me.id);
        await db.runAsync('UPDATE group_messages SET read_by = ? WHERE id = ?', [JSON.stringify(read), r.id]);
      }
    }
    res.json(rows);
  } catch (err) {
    console.error('Get group messages error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- UNREAD COUNTS ----------
app.get('/api/unread', requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    const priv = await db.allAsync('SELECT * FROM private_messages');
    const groupsMsgs = await db.allAsync('SELECT * FROM group_messages');

    const privateCounts = {};
    priv.forEach(m => {
      let read = [];
      if (m.read_by) {
        try { read = JSON.parse(m.read_by); } catch(e){ read = []; }
      }
      const other = (m.from_id === me.id) ? m.to_id : m.from_id;
      if (m.to_id === me.id && !read.includes(me.id)) {
        privateCounts[other] = (privateCounts[other] || 0) + 1;
      }
    });

    const groupCounts = {};
    groupsMsgs.forEach(m => {
      let read = [];
      if (m.read_by) {
        try { read = JSON.parse(m.read_by); } catch(e){ read = []; }
      }
      if (!read.includes(me.id)) {
        groupCounts[m.group_id] = (groupCounts[m.group_id] || 0) + 1;
      }
    });

    res.json({ global: 0, private: privateCounts, groups: groupCounts });
  } catch (err) {
    console.error('Get unread error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- SOCKET.IO presence & rooms ----------
const socketToUser = new Map();      // socketId -> userId
const userSocketCount = new Map();   // userId -> number

io.on('connection', (socket) => {
  socket.on('online', async (userId) => {
    if (!userId) return;
    socketToUser.set(socket.id, userId);
    const prev = userSocketCount.get(userId) || 0;
    userSocketCount.set(userId, prev + 1);

    // persistent mark online true
    await db.runAsync('UPDATE users SET online = 1 WHERE id = ?', [userId]);
    io.emit('presence_update', { id: userId, online: true });
  });

  socket.on('join_private', ({ me, other }) => {
    if (!me || !other) return;
    socket.join(`pm-${me}-${other}`);
    socket.join(`pm-${other}-${me}`);
  });

  socket.on('join_group', (groupId) => {
    if (typeof groupId === 'undefined' || groupId === null) return;
    socket.join(`group-${groupId}`);
  });

  socket.on('disconnect', async () => {
    const userId = socketToUser.get(socket.id);
    socketToUser.delete(socket.id);
    if (userId) {
      const prev = userSocketCount.get(userId) || 1;
      const next = Math.max(0, prev - 1);
      userSocketCount.set(userId, next);
      if (next === 0) {
        await db.runAsync('UPDATE users SET online = 0 WHERE id = ?', [userId]);
        io.emit('presence_update', { id: userId, online: false });
      }
    }
  });
});

// SPA support (serve index for any non-api routes)
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// start
server.listen(PORT, () => {
  console.log('Server running on port', PORT);
});
