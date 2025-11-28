// server.js
// ChatNodo — servidor con SQLite + Socket.io
// Requisitos: npm i sqlite3 bcryptjs express-session cookie-parser body-parser

const express = require("express");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// SQLite DB
const DB_PATH = path.join(DATA_DIR, "database.sqlite");
const db = new sqlite3.Database(DB_PATH);

// promisified helpers
const dbRun = (sql, params=[]) => new Promise((res, rej) => {
  db.run(sql, params, function(err) { if (err) rej(err); else res(this); });
});
const dbGet = (sql, params=[]) => new Promise((res, rej) => {
  db.get(sql, params, (err, row) => { if (err) rej(err); else res(row); });
});
const dbAll = (sql, params=[]) => new Promise((res, rej) => {
  db.all(sql, params, (err, rows) => { if (err) rej(err); else res(rows); });
});

// init tables
(async function initDb(){
  try {
    // users
    await dbRun(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      password_hash TEXT,
      avatar TEXT,
      description TEXT,
      online INTEGER DEFAULT 0
    );`);
    // contacts (bidirectional entries)
    await dbRun(`CREATE TABLE IF NOT EXISTS contacts (
      id INTEGER PRIMARY KEY,
      user_id INTEGER,
      contact_id INTEGER,
      UNIQUE(user_id, contact_id)
    );`);
    // friend requests
    await dbRun(`CREATE TABLE IF NOT EXISTS friend_requests (
      id INTEGER PRIMARY KEY,
      from_id INTEGER,
      to_id INTEGER,
      created_at TEXT
    );`);
    // global messages
    await dbRun(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY,
      user_id INTEGER,
      username TEXT,
      text TEXT,
      created_at TEXT
    );`);
    // private messages
    await dbRun(`CREATE TABLE IF NOT EXISTS private_messages (
      id INTEGER PRIMARY KEY,
      from_id INTEGER,
      to_id INTEGER,
      text TEXT,
      created_at TEXT,
      read_by TEXT -- JSON array of user ids
    );`);
    // groups
    await dbRun(`CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY,
      name TEXT,
      created_by INTEGER
    );`);
    // group members
    await dbRun(`CREATE TABLE IF NOT EXISTS group_members (
      id INTEGER PRIMARY KEY,
      group_id INTEGER,
      user_id INTEGER,
      UNIQUE(group_id, user_id)
    );`);
    // group messages
    await dbRun(`CREATE TABLE IF NOT EXISTS group_messages (
      id INTEGER PRIMARY KEY,
      group_id INTEGER,
      from_id INTEGER,
      text TEXT,
      created_at TEXT,
      read_by TEXT
    );`);
    console.log("Database initialized.");
  } catch (e) {
    console.error("DB init error", e);
  }
})();

// express middleware
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("trust proxy", 1);

app.use(session({
  secret: process.env.SESSION_SECRET || "secret123",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000*60*60*24*7
  }
}));

function requireAuth(req, res, next){
  if(req.session && req.session.user) return next();
  res.status(401).json({ error: "Unauthorized" });
}

// helper: get persistent user record
async function getUserBySession(req) {
  if(!req.session || !req.session.user) return null;
  const u = await dbGet("SELECT * FROM users WHERE id = ?", [req.session.user.id]);
  return u || null;
}

/* ---------- AUTH ---------- */
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if(!username || !password) return res.status(400).json({ error: "Missing username/password" });

    const exists = await dbGet("SELECT id FROM users WHERE username = ?", [username]);
    if (exists) return res.status(400).json({ error: "Username already exists" });

    const hash = await bcrypt.hash(password, 10);
    const info = await dbRun("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, hash]);
    const id = info.lastID;
    req.session.user = { id, username };
    res.json(req.session.user);
  } catch (e) {
    console.error("register error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if(!username || !password) return res.status(400).json({ error: "Missing username/password" });

    const user = await dbGet("SELECT * FROM users WHERE username = ?", [username]);
    if(!user) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(400).json({ error: "Invalid credentials" });

    req.session.user = { id: user.id, username: user.username };
    res.json(req.session.user);
  } catch (e) {
    console.error("login error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", async (req, res) => {
  try {
    if(!req.session || !req.session.user) return res.json({ user: null });
    const u = await dbGet("SELECT id, username, avatar, description, online FROM users WHERE id = ?", [req.session.user.id]);
    if(!u) return res.json({ user: null });
    res.json({ user: { id: u.id, username: u.username, avatar: u.avatar, description: u.description || "", online: !!u.online } });
  } catch (e) {
    console.error("me error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/me/profile", requireAuth, async (req, res) => {
  try {
    const { description, avatar } = req.body || {};
    const user = await getUserBySession(req);
    if(!user) return res.status(400).json({ error: "User not found" });

    if(typeof description === "string") await dbRun("UPDATE users SET description = ? WHERE id = ?", [description, user.id]);
    if(avatar === null) await dbRun("UPDATE users SET avatar = NULL WHERE id = ?", [user.id]);
    else if (typeof avatar === "string" && avatar.startsWith("data:")) await dbRun("UPDATE users SET avatar = ? WHERE id = ?", [avatar, user.id]);

    res.json({ ok: true });
  } catch (e) {
    console.error("profile error", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- FRIEND REQUESTS ---------- */
app.post("/api/friend/request", requireAuth, async (req, res) => {
  try {
    const { to } = req.body || {};
    if(!to) return res.status(400).json({ error: "Missing 'to' username" });

    const me = await getUserBySession(req);
    const target = await dbGet("SELECT * FROM users WHERE username = ?", [to]);
    if(!me) return res.status(400).json({ error: "Authenticated user not found" });
    if(!target) return res.status(400).json({ error: "User not found" });
    if(me.id === target.id) return res.status(400).json({ error: "Cannot add yourself" });

    // if already contacts
    const existingContact = await dbGet("SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?", [me.id, target.id]);
    if(existingContact) return res.status(400).json({ error: "Already contact" });

    const existReq = await dbGet("SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?", [me.id, target.id]);
    if(existReq) return res.status(400).json({ error: "Request already sent" });

    await dbRun("INSERT INTO friend_requests (from_id, to_id, created_at) VALUES (?, ?, ?)", [me.id, target.id, new Date().toISOString()]);

    io.emit("friend_request", { fromId: me.id, fromName: me.username, toId: target.id });
    res.json({ ok: true });
  } catch (e) {
    console.error("friend request error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/friend/requests", requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    const rows = await dbAll("SELECT fr.id, fr.from_id, fr.to_id, fr.created_at, u.username as fromName FROM friend_requests fr JOIN users u ON u.id = fr.from_id WHERE fr.to_id = ?", [me.id]);
    const mapped = rows.map(r => ({ id: r.id, from: r.from_id, fromName: r.fromName, created_at: r.created_at }));
    res.json(mapped);
  } catch (e) {
    console.error("friend requests get error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/friend/accept", requireAuth, async (req, res) => {
  try {
    const { requestId } = req.body || {};
    if(!requestId) return res.status(400).json({ error: "Missing requestId" });

    const reqRow = await dbGet("SELECT * FROM friend_requests WHERE id = ?", [requestId]);
    if(!reqRow) return res.status(400).json({ error: "Request not found" });

    // add to contacts both ways if not exist
    await dbRun("DELETE FROM friend_requests WHERE id = ?", [requestId]);
    const a = reqRow.from_id;
    const b = reqRow.to_id;
    // insert both directions
    await dbRun("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)", [a,b]);
    await dbRun("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)", [b,a]);

    io.emit("friend_accepted", { from: a, to: b });
    res.json({ ok: true });
  } catch (e) {
    console.error("friend accept error", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- CONTACTS ---------- */
app.post("/api/add-contact", requireAuth, async (req, res) => {
  try {
    const { username } = req.body || {};
    if(!username) return res.status(400).json({ error: "Missing username" });

    const me = await getUserBySession(req);
    const other = await dbGet("SELECT * FROM users WHERE username = ?", [username]);
    if(!me) return res.status(400).json({ error: "Authenticated user not found" });
    if(!other) return res.status(400).json({ error: "No existe ese usuario" });

    // add contact both ways
    await dbRun("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)", [me.id, other.id]);
    await dbRun("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)", [other.id, me.id]);

    io.emit("contact_added", { by: me.id, contact: { id: other.id, username: other.username } });
    res.json({ ok: true });
  } catch (e) {
    console.error("add contact error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/contacts", requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    if(!me) return res.json([]);
    const rows = await dbAll("SELECT u.id, u.username, u.avatar, u.description, u.online FROM users u JOIN contacts c ON c.contact_id = u.id WHERE c.user_id = ?", [me.id]);
    res.json(rows.map(r => ({ id: r.id, username: r.username, avatar: r.avatar, description: r.description || "", online: !!r.online })));
  } catch (e) {
    console.error("get contacts error", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- GLOBAL CHAT ---------- */
app.get("/api/messages", async (req, res) => {
  try {
    const rows = await dbAll("SELECT * FROM messages ORDER BY id DESC LIMIT 200", []);
    res.json(rows.reverse());
  } catch (e) {
    console.error("get messages error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/messages", requireAuth, async (req, res) => {
  try {
    const { text } = req.body || {};
    if(!text) return res.status(400).json({ error: "Missing text" });
    const me = await getUserBySession(req);
    const info = await dbRun("INSERT INTO messages (user_id, username, text, created_at) VALUES (?,?,?,?)", [me.id, me.username, text, new Date().toISOString()]);
    const msg = { id: info.lastID, user_id: me.id, username: me.username, text, created_at: new Date().toISOString() };
    io.emit("message", msg);
    res.json(msg);
  } catch (e) {
    console.error("post message error", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- PRIVATE MESSAGES ---------- */
app.post("/api/private/send", requireAuth, async (req, res) => {
  try {
    const { to, text } = req.body || {};
    if(!to || !text) return res.status(400).json({ error: "Missing to/text" });
    const toId = parseInt(to);
    const me = await getUserBySession(req);
    const info = await dbRun("INSERT INTO private_messages (from_id, to_id, text, created_at, read_by) VALUES (?,?,?,?,?)",
      [me.id, toId, text, new Date().toISOString(), JSON.stringify([me.id])]);
    const msg = { id: info.lastID, from: me.id, to: toId, text, created_at: new Date().toISOString(), read_by: [me.id] };

    // emit to private rooms
    io.to(`pm-${msg.from}-${msg.to}`).emit("private_message", msg);
    io.to(`pm-${msg.to}-${msg.from}`).emit("private_message", msg);

    res.json(msg);
  } catch (e) {
    console.error("private send error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/private/:withId", requireAuth, async (req, res) => {
  try {
    const withId = parseInt(req.params.withId);
    const me = await getUserBySession(req);
    const rows = await dbAll("SELECT * FROM private_messages WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY id ASC",
      [me.id, withId, withId, me.id]);

    // mark read for current user
    let changed = false;
    const all = [];
    for(const r of rows){
      let read_by = [];
      try { read_by = JSON.parse(r.read_by || "[]"); } catch(e){ read_by = []; }
      if(!read_by.includes(me.id)){ read_by.push(me.id); changed = true; r.read_by = JSON.stringify(read_by); await dbRun("UPDATE private_messages SET read_by = ? WHERE id = ?", [r.read_by, r.id]); }
      all.push({ id: r.id, from: r.from_id, to: r.to_id, text: r.text, created_at: r.created_at, read_by: JSON.parse(r.read_by) });
    }

    res.json(all);
  } catch (e) {
    console.error("get private messages error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/private/mark-read", requireAuth, async (req, res) => {
  try {
    const { withId } = req.body || {};
    if(!withId) return res.status(400).json({ error: "Missing withId" });
    const me = await getUserBySession(req);

    const rows = await dbAll("SELECT * FROM private_messages WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
      [withId, me.id, me.id, withId]);

    for(const r of rows){
      let read_by = [];
      try { read_by = JSON.parse(r.read_by || "[]"); } catch(e){ read_by = []; }
      if(!read_by.includes(me.id)){ read_by.push(me.id); await dbRun("UPDATE private_messages SET read_by = ? WHERE id = ?", [JSON.stringify(read_by), r.id]); }
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("private mark read error", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- GROUPS ---------- */
app.post("/api/groups/create", requireAuth, async (req, res) => {
  try {
    const { name, members } = req.body || {};
    if(!name) return res.status(400).json({ error: "Missing group name" });
    const me = await getUserBySession(req);

    const info = await dbRun("INSERT INTO groups (name, created_by) VALUES (?, ?)", [name, me.id]);
    const groupId = info.lastID;
    // add creator as member
    await dbRun("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", [groupId, me.id]);

    // add other members if provided
    if(Array.isArray(members)){
      for(const m of members){
        const mid = parseInt(m);
        if(!isNaN(mid)) await dbRun("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)", [groupId, mid]);
      }
    }
    const group = await dbGet("SELECT * FROM groups WHERE id = ?", [groupId]);
    io.emit("group_created", { id: group.id, name: group.name, members: [] });
    res.json(group);
  } catch (e) {
    console.error("create group error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/groups/add-member", requireAuth, async (req, res) => {
  try {
    const { group_id, username } = req.body || {};
    if(!group_id || !username) return res.status(400).json({ error: "Missing group_id/username" });
    const me = await getUserBySession(req);
    const g = await dbGet("SELECT * FROM groups WHERE id = ?", [group_id]);
    if(!g) return res.status(400).json({ error: "Group not found" });

    // ensure requester is a member
    const isMember = await dbGet("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", [group_id, me.id]);
    if(!isMember) return res.status(403).json({ error: "Not a member" });

    const u = await dbGet("SELECT * FROM users WHERE username = ?", [username]);
    if(!u) return res.status(400).json({ error: "User not found" });

    await dbRun("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)", [group_id, u.id]);

    // emit event
    io.to(`group-${group_id}`).emit("group_member_added", { group_id: group_id, user: { id: u.id, username: u.username } });
    res.json({ ok: true, group_id: group_id, user: { id: u.id, username: u.username } });
  } catch (e) {
    console.error("add group member error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/groups", requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    const rows = await dbAll("SELECT g.id, g.name, g.created_by, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as members_count FROM groups g JOIN group_members gm2 ON gm2.group_id = g.id WHERE gm2.user_id = ?", [me.id]);
    res.json(rows.map(r => ({ id: r.id, name: r.name, created_by: r.created_by, members: r.members_count })));
  } catch (e) {
    console.error("get groups error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/groups/send", requireAuth, async (req, res) => {
  try {
    const { group_id, text } = req.body || {};
    if(!group_id || !text) return res.status(400).json({ error: "Missing group_id/text" });
    const me = await getUserBySession(req);

    const info = await dbRun("INSERT INTO group_messages (group_id, from_id, text, created_at, read_by) VALUES (?,?,?,?,?)",
      [group_id, me.id, text, new Date().toISOString(), JSON.stringify([me.id])]);
    const msg = { id: info.lastID, group_id: group_id, from: me.id, text, created_at: new Date().toISOString(), read_by: [me.id] };

    io.to(`group-${group_id}`).emit("group_message", msg);
    res.json(msg);
  } catch (e) {
    console.error("group send error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/groups/messages/:id", requireAuth, async (req, res) => {
  try {
    const gid = parseInt(req.params.id);
    const me = await getUserBySession(req);
    const rows = await dbAll("SELECT * FROM group_messages WHERE group_id = ? ORDER BY id ASC", [gid]);
    const out = [];
    for(const r of rows){
      let read_by = [];
      try { read_by = JSON.parse(r.read_by || "[]"); } catch(e){ read_by = []; }
      if(!read_by.includes(me.id)){ read_by.push(me.id); await dbRun("UPDATE group_messages SET read_by = ? WHERE id = ?", [JSON.stringify(read_by), r.id]); }
      out.push({ id: r.id, group_id: r.group_id, from: r.from_id, text: r.text, created_at: r.created_at, read_by });
    }
    res.json(out);
  } catch (e) {
    console.error("get group messages error", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- UNREAD COUNTS ---------- */
app.get("/api/unread", requireAuth, async (req, res) => {
  try {
    const me = await getUserBySession(req);
    const priv = await dbAll("SELECT * FROM private_messages", []);
    const groups = await dbAll("SELECT * FROM group_messages", []);

    const privateCounts = {};
    for(const m of priv){
      const other = (m.from_id === me.id) ? m.to_id : m.from_id;
      let read_by = [];
      try { read_by = JSON.parse(m.read_by || "[]"); } catch(e){ read_by = []; }
      if(m.to_id === me.id && !read_by.includes(me.id)) {
        privateCounts[other] = (privateCounts[other] || 0) + 1;
      }
    }

    const groupCounts = {};
    for(const m of groups){
      let read_by = [];
      try { read_by = JSON.parse(m.read_by || "[]"); } catch(e){ read_by = []; }
      if(!read_by.includes(me.id)){
        groupCounts[m.group_id] = (groupCounts[m.group_id] || 0) + 1;
      }
    }

    res.json({ global: 0, private: privateCounts, groups: groupCounts });
  } catch (e) {
    console.error("get unread error", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- SOCKET.IO presence & rooms ---------- */
const socketToUser = new Map();
const userSocketCount = new Map();

io.on("connection", (socket) => {
  // when client says they're online (passes their user id)
  socket.on("online", async (userId) => {
    if(!userId) return;
    socketToUser.set(socket.id, userId);
    const prev = userSocketCount.get(userId) || 0;
    userSocketCount.set(userId, prev + 1);

    // mark persistent online
    await dbRun("UPDATE users SET online = 1 WHERE id = ?", [userId]);
    io.emit("presence_update", { id: userId, online: true });
  });

  socket.on("join_private", ({ me, other }) => {
    if(!me || !other) return;
    socket.join(`pm-${me}-${other}`);
    socket.join(`pm-${other}-${me}`);
  });

  socket.on("join_group", (groupId) => {
    if(typeof groupId === "undefined" || groupId === null) return;
    socket.join(`group-${groupId}`);
  });

  socket.on("disconnect", async () => {
    const userId = socketToUser.get(socket.id);
    socketToUser.delete(socket.id);
    if(userId){
      const prev = userSocketCount.get(userId) || 1;
      const next = Math.max(0, prev - 1);
      userSocketCount.set(userId, next);
      if(next === 0){
        await dbRun("UPDATE users SET online = 0 WHERE id = ?", [userId]);
        io.emit("presence_update", { id: userId, online: false });
      }
    }
  });
});

// SPA fallback
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

server.listen(PORT, () => {
  console.log("Server listening on port", PORT);
});
