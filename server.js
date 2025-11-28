// ============================
// ChatNodo — Servidor Completo con SQLite
// Compatible con Render, Node.js 18-20
// ============================

// Librerías principales
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

// -----------------------------
// Inicialización
// -----------------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 8080;

const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, "database.sqlite");
console.log("USING SQLITE DB AT:", DB_PATH);


// Helpers promesas para sqlite
const dbRun = (sql, params = []) =>
  new Promise((res, rej) => db.run(sql, params, function (err) { err ? rej(err) : res(this); }));

const dbGet = (sql, params = []) =>
  new Promise((res, rej) => db.get(sql, params, (err, row) => err ? rej(err) : res(row)));

const dbAll = (sql, params = []) =>
  new Promise((res, rej) => db.all(sql, params, (err, rows) => err ? rej(err) : res(rows)));

// -----------------------------
// CREAR TABLAS
// -----------------------------
(async function initDb() {
  try {
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        avatar TEXT,
        description TEXT,
        online INTEGER DEFAULT 0
      );
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        contact_id INTEGER,
        UNIQUE(user_id, contact_id)
      );
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY,
        from_id INTEGER,
        to_id INTEGER,
        created_at TEXT
      );
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        username TEXT,
        text TEXT,
        created_at TEXT
      );
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS private_messages (
        id INTEGER PRIMARY KEY,
        from_id INTEGER,
        to_id INTEGER,
        text TEXT,
        created_at TEXT,
        read_by TEXT
      );
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY,
        name TEXT,
        created_by INTEGER
      );
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY,
        group_id INTEGER,
        user_id INTEGER,
        UNIQUE(group_id, user_id)
      );
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS group_messages (
        id INTEGER PRIMARY KEY,
        group_id INTEGER,
        from_id INTEGER,
        text TEXT,
        created_at TEXT,
        read_by TEXT
      );
    `);

    console.log("SQLite DB inicializada correctamente.");
  } catch (e) {
    console.error("Error inicializando DB:", e);
  }
})();

// -----------------------------
// MIDDLEWARE
// -----------------------------
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("trust proxy", 1);

app.use(
  session({
    secret: "secret123",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: "Unauthorized" });
}

async function getUserBySession(req) {
  if (!req.session || !req.session.user) return null;
  return await dbGet("SELECT * FROM users WHERE id = ?", [req.session.user.id]);
}

// -----------------------------
// AUTH
// -----------------------------
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    const exists = await dbGet("SELECT id FROM users WHERE username = ?", [username]);
    if (exists) return res.status(400).json({ error: "Username exists" });

    const hash = await bcrypt.hash(password, 10);
    const info = await dbRun(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, hash]
    );

    req.session.user = { id: info.lastID, username };
    res.json(req.session.user);
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await dbGet("SELECT * FROM users WHERE username = ?", [username]);
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    req.session.user = { id: user.id, username: user.username };
    res.json(req.session.user);
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", async (req, res) => {
  const u = await getUserBySession(req);
  if (!u) return res.json({ user: null });
  res.json({
    user: {
      id: u.id,
      username: u.username,
      avatar: u.avatar,
      description: u.description,
      online: !!u.online,
    },
  });
});

// -----------------------------
// PERFIL
// -----------------------------
app.post("/api/me/profile", requireAuth, async (req, res) => {
  try {
    const { description, avatar } = req.body;
    const u = await getUserBySession(req);

    await dbRun("UPDATE users SET description=?, avatar=? WHERE id=?", [
      description || "",
      avatar || null,
      u.id,
    ]);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// -----------------------------
// CONTACTOS
// -----------------------------
app.post("/api/add-contact", requireAuth, async (req, res) => {
  try {
    const { username } = req.body;
    const me = await getUserBySession(req);
    const other = await dbGet("SELECT * FROM users WHERE username=?", [username]);

    if (!other) return res.status(400).json({ error: "No existe ese usuario" });

    await dbRun("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)", [
      me.id,
      other.id,
    ]);
    await dbRun("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)", [
      other.id,
      me.id,
    ]);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/contacts", requireAuth, async (req, res) => {
  const me = await getUserBySession(req);

  const rows = await dbAll(
    "SELECT u.id, u.username, u.avatar, u.description, u.online FROM contacts c JOIN users u ON u.id = c.contact_id WHERE c.user_id = ?",
    [me.id]
  );

  res.json(rows);
});

// -----------------------------
// GLOBAL CHAT
// -----------------------------
app.get("/api/messages", async (req, res) => {
  const rows = await dbAll("SELECT * FROM messages ORDER BY id DESC LIMIT 200");
  res.json(rows.reverse());
});

app.post("/api/messages", requireAuth, async (req, res) => {
  const { text } = req.body;
  const me = await getUserBySession(req);

  const info = await dbRun(
    "INSERT INTO messages (user_id, username, text, created_at) VALUES (?,?,?,?)",
    [me.id, me.username, text, new Date().toISOString()]
  );

  const msg = {
    id: info.lastID,
    user_id: me.id,
    username: me.username,
    text,
    created_at: new Date().toISOString(),
  };

  io.emit("message", msg);
  res.json(msg);
});

// -----------------------------
// MENSAJES PRIVADOS
// -----------------------------
app.post("/api/private/send", requireAuth, async (req, res) => {
  const { to, text } = req.body;
  const me = await getUserBySession(req);

  const info = await dbRun(
    "INSERT INTO private_messages (from_id, to_id, text, created_at, read_by) VALUES (?,?,?,?,?)",
    [me.id, to, text, new Date().toISOString(), JSON.stringify([me.id])]
  );

  const msg = {
    id: info.lastID,
    from_id: me.id,
    to_id: to,
    text,
    created_at: new Date().toISOString(),
    read_by: [me.id],
  };

  io.to(`pm-${me.id}-${to}`).emit("private_message", msg);
  io.to(`pm-${to}-${me.id}`).emit("private_message", msg);

  res.json(msg);
});

app.get("/api/private/:withId", requireAuth, async (req, res) => {
  const withId = parseInt(req.params.withId);
  const me = await getUserBySession(req);

  const rows = await dbAll(
    "SELECT * FROM private_messages WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) ORDER BY id ASC",
    [me.id, withId, withId, me.id]
  );

  const out = rows.map((r) => ({
    id: r.id,
    from: r.from_id,
    to: r.to_id,
    text: r.text,
    created_at: r.created_at,
    read_by: JSON.parse(r.read_by || "[]"),
  }));

  res.json(out);
});

// -----------------------------
// GRUPOS
// -----------------------------
app.post("/api/groups/create", requireAuth, async (req, res) => {
  const { name, members } = req.body;
  const me = await getUserBySession(req);

  const info = await dbRun("INSERT INTO groups (name, created_by) VALUES (?,?)", [
    name,
    me.id,
  ]);

  const groupId = info.lastID;
  await dbRun("INSERT INTO group_members (group_id, user_id) VALUES (?,?)", [
    groupId,
    me.id,
  ]);

  if (Array.isArray(members)) {
    for (const m of members) {
      await dbRun(
        "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)",
        [groupId, m]
      );
    }
  }

  io.emit("group_created", { id: groupId, name });
  res.json({ id: groupId, name });
});

app.post("/api/groups/add-member", requireAuth, async (req, res) => {
  const { group_id, username } = req.body;
  const me = await getUserBySession(req);

  const g = await dbGet("SELECT * FROM groups WHERE id=?", [group_id]);
  if (!g) return res.status(400).json({ error: "Group not found" });

  const target = await dbGet("SELECT * FROM users WHERE username=?", [username]);
  if (!target) return res.status(400).json({ error: "User not found" });

  await dbRun(
    "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)",
    [group_id, target.id]
  );

  io.to(`group-${group_id}`).emit("group_member_added", {
    group_id,
    user: { id: target.id, username: target.username },
  });

  res.json({ ok: true });
});

app.get("/api/groups", requireAuth, async (req, res) => {
  const me = await getUserBySession(req);

  const rows = await dbAll(
    "SELECT g.id, g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ?",
    [me.id]
  );

  res.json(rows);
});

app.post("/api/groups/send", requireAuth, async (req, res) => {
  const { group_id, text } = req.body;
  const me = await getUserBySession(req);

  const info = await dbRun(
    "INSERT INTO group_messages (group_id, from_id, text, created_at, read_by) VALUES (?,?,?,?,?)",
    [group_id, me.id, text, new Date().toISOString(), JSON.stringify([me.id])]
  );

  const msg = {
    id: info.lastID,
    group_id,
    from: me.id,
    text,
    created_at: new Date().toISOString(),
    read_by: [me.id],
  };

  io.to(`group-${group_id}`).emit("group_message", msg);
  res.json(msg);
});

// -----------------------------
// SOCKET.IO
// -----------------------------
const socketToUser = new Map();
const userSocketCount = new Map();

io.on("connection", (socket) => {
  socket.on("online", async (userId) => {
    if (!userId) return;

    socketToUser.set(socket.id, userId);
    userSocketCount.set(userId, (userSocketCount.get(userId) || 0) + 1);

    await dbRun("UPDATE users SET online=1 WHERE id=?", [userId]);
    io.emit("presence_update", { id: userId, online: true });
  });

  socket.on("join_private", ({ me, other }) => {
    socket.join(`pm-${me}-${other}`);
    socket.join(`pm-${other}-${me}`);
  });

  socket.on("join_group", (groupId) => {
    socket.join(`group-${groupId}`);
  });

  socket.on("disconnect", async () => {
    const userId = socketToUser.get(socket.id);
    socketToUser.delete(socket.id);

    if (userId) {
      userSocketCount.set(userId, userSocketCount.get(userId) - 1);

      if (userSocketCount.get(userId) <= 0) {
        await dbRun("UPDATE users SET online=0 WHERE id=?", [userId]);
        io.emit("presence_update", { id: userId, online: false });
      }
    }
  });
});

// -----------------------------
// SPA fallback
// -----------------------------
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// -----------------------------
// START SERVER
// -----------------------------
server.listen(PORT, () => console.log("Servidor corriendo en puerto", PORT));
