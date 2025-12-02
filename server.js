// Updated server.js — adds contacts, private messages and groups (minimal implementation)
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

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, "data", "database.db");

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({ secret: "chat-secret", resave: false, saveUninitialized: true }));
app.use(express.static(path.join(__dirname, "public")));

// --- open/create DB and ensure schema
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER,
    to_id INTEGER,        -- nullable, user id for private messages
    group_id INTEGER,     -- nullable, group id for group messages
    content TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    contact_id INTEGER,
    UNIQUE(user_id, contact_id)
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    creator_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    user_id INTEGER,
    UNIQUE(group_id, user_id)
  );`);
});

// --- Helper: require login
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Not authenticated" });
}

// --- Auth: register / login / logout
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "missing" });
  const hash = bcrypt.hashSync(password, 8);
  db.run("INSERT INTO users(username,password) VALUES(?,?)", [username, hash], function(err) {
    if (err) return res.status(400).json({ error: "username exists" });
    req.session.userId = this.lastID;
    req.session.username = username;
    res.json({ id: this.lastID, username });
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT id,password FROM users WHERE username = ?", [username], (err, row) => {
    if (err || !row) return res.status(400).json({ error: "invalid" });
    if (!bcrypt.compareSync(password, row.password)) return res.status(400).json({ error: "invalid" });
    req.session.userId = row.id;
    req.session.username = username;
    res.json({ id: row.id, username });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(()=>res.json({ ok: true }));
});

// --- Contacts endpoints
app.post("/api/add-contact", requireAuth, (req, res) => {
  const { contactUsername } = req.body;
  const userId = req.session.userId;
  db.get("SELECT id FROM users WHERE username = ?", [contactUsername], (err, row) => {
    if (err || !row) return res.status(404).json({ error: "user not found" });
    const contactId = row.id;
    if (contactId === userId) return res.status(400).json({ error: "cannot add yourself" });
    db.run("INSERT OR IGNORE INTO contacts(user_id, contact_id) VALUES(?,?)", [userId, contactId], function(err) {
      if (err) return res.status(500).json({ error: "db" });
      res.json({ ok: true, contactId });
    });
  });
});

app.get("/api/contacts", requireAuth, (req, res) => {
  const userId = req.session.userId;
  db.all(`SELECT u.id, u.username FROM users u
    JOIN contacts c ON c.contact_id = u.id
    WHERE c.user_id = ?`, [userId], (err, rows) => {
      if (err) return res.status(500).json({ error: "db" });
      res.json(rows);
    });
});

// --- Groups endpoints
app.post("/api/create-group", requireAuth, (req, res) => {
  const { name, members } = req.body; // members: array of usernames to add (optional)
  const creator = req.session.userId;
  db.run("INSERT INTO groups(name, creator_id) VALUES(?,?)", [name, creator], function(err) {
    if (err) return res.status(500).json({ error: "db" });
    const groupId = this.lastID;
    // add creator as member
    db.run("INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES(?,?)", [groupId, creator]);
    if (Array.isArray(members)) {
      members.forEach(username => {
        db.get("SELECT id FROM users WHERE username = ?", [username], (e, row) => {
          if (row) db.run("INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES(?,?)", [groupId, row.id]);
        });
      });
    }
    res.json({ ok: true, groupId });
  });
});

app.get("/api/groups", requireAuth, (req, res) => {
  const userId = req.session.userId;
  db.all(`SELECT g.id, g.name, g.creator_id FROM groups g
    JOIN group_members gm ON gm.group_id = g.id
    WHERE gm.user_id = ?`, [userId], (err, rows) => {
      if (err) return res.status(500).json({ error: "db" });
      res.json(rows);
    });
});

// join group (server-side: add as member)
app.post("/api/join-group", requireAuth, (req, res) => {
  const userId = req.session.userId;
  const { groupId } = req.body;
  db.run("INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES(?,?)", [groupId, userId], function(err) {
    if (err) return res.status(500).json({ error: "db" });
    res.json({ ok: true });
  });
});

// --- Messages retrieval
app.get("/api/messages", requireAuth, (req, res) => {
  const userId = req.session.userId;
  const { type } = req.query; // 'global' | 'private' | 'group'
  if (type === "global") {
    db.all("SELECT m.*, u.username as from_username FROM messages m LEFT JOIN users u ON u.id = m.from_id WHERE m.group_id IS NULL AND m.to_id IS NULL ORDER BY m.timestamp ASC", [], (err, rows) => {
      res.json(rows || []);
    });
  } else if (type === "private") {
    const withId = parseInt(req.query.with);
    if (!withId) return res.status(400).json({ error: "missing with" });
    db.all(`SELECT m.*, u.username as from_username FROM messages m 
      LEFT JOIN users u ON u.id = m.from_id
      WHERE (m.from_id = ? AND m.to_id = ?) OR (m.from_id = ? AND m.to_id = ?)
      ORDER BY m.timestamp ASC`, [userId, withId, withId, userId], (err, rows) => {
        res.json(rows || []);
      });
  } else if (type === "group") {
    const groupId = parseInt(req.query.group_id);
    if (!groupId) return res.status(400).json({ error: "missing group_id" });
    db.all(`SELECT m.*, u.username as from_username FROM messages m LEFT JOIN users u ON u.id = m.from_id WHERE m.group_id = ? ORDER BY m.timestamp ASC`, [groupId], (err, rows) => {
      res.json(rows || []);
    });
  } else {
    res.status(400).json({ error: "invalid type" });
  }
});

// --- Send message (via REST) - also Socket events will be used
app.post("/api/send-message", requireAuth, (req, res) => {
  const from = req.session.userId;
  const { content, toId, groupId } = req.body;
  db.run("INSERT INTO messages(from_id, to_id, group_id, content) VALUES(?,?,?,?)", [from, toId || null, groupId || null, content], function(err) {
    if (err) return res.status(500).json({ error: "db" });
    const messageId = this.lastID;
    db.get("SELECT m.*, u.username as from_username FROM messages m LEFT JOIN users u ON u.id = m.from_id WHERE m.id = ?", [messageId], (err, msg) => {
      // emit via socket
      if (groupId) {
        io.to("group_" + groupId).emit("new_message", msg);
      } else if (toId) {
        io.to("user_" + toId).emit("new_message", msg);
        io.to("user_" + from).emit("new_message", msg);
      } else {
        io.emit("new_message", msg);
      }
      res.json(msg);
    });
  });
});

// --- SPA fallback
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- Socket.IO logic
// map userId -> socket.id (supports single connection per user for simplicity)
const userSocket = new Map();

io.use((socket, next) => {
  // simple cookie based session reading
  const cookie = socket.handshake.headers.cookie || "";
  // express-session cookie name is connect.sid by default; but it's signed — for simplicity we'll expect query auth
  next();
});

io.on("connection", (socket) => {
  // the client must send 'auth' event with { userId }
  socket.on("auth", (data) => {
    const userId = data && data.userId;
    if (!userId) return;
    socket.userId = userId;
    userSocket.set(String(userId), socket.id);
    // join personal room
    socket.join("user_" + userId);
    // also join all groups the user is member of
    db.all("SELECT group_id FROM group_members WHERE user_id = ?", [userId], (err, rows) => {
      if (rows) {
        rows.forEach(r => socket.join("group_" + r.group_id));
      }
    });
  });

  socket.on("send_message", (payload) => {
    // payload: { content, toId, groupId }
    const from = socket.userId;
    if (!from) return;
    const { content, toId, groupId } = payload;
    db.run("INSERT INTO messages(from_id, to_id, group_id, content) VALUES(?,?,?,?)", [from, toId || null, groupId || null, content], function(err) {
      if (err) return;
      const id = this.lastID;
      db.get("SELECT m.*, u.username as from_username FROM messages m LEFT JOIN users u ON u.id = m.from_id WHERE m.id = ?", [id], (err, msg) => {
        if (groupId) {
          io.to("group_" + groupId).emit("new_message", msg);
        } else if (toId) {
          io.to("user_" + toId).emit("new_message", msg);
          io.to("user_" + from).emit("new_message", msg);
        } else {
          io.emit("new_message", msg);
        }
      });
    });
  });

  socket.on("disconnect", () => {
    if (socket.userId) userSocket.delete(String(socket.userId));
  });
});

server.listen(PORT, () => console.log("Servidor corriendo en puerto", PORT));

