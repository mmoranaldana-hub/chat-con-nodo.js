// server.js (PEGA TODO ESTO)
const express = require("express");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 8080;

// ---------- JSON DATABASE (NO SQLITE) ----------
const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const usersFile = path.join(dataDir, "users.json");
const messagesFile = path.join(dataDir, "messages.json");
const privateMessagesFile = path.join(dataDir, "private_messages.json");
const groupsFile = path.join(dataDir, "groups.json");
const groupMessagesFile = path.join(dataDir, "group_messages.json");

function ensureFile(file, defaultContent) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(defaultContent, null, 2));
  }
}

ensureFile(usersFile, []);
ensureFile(messagesFile, []);
ensureFile(privateMessagesFile, []);
ensureFile(groupsFile, []);
ensureFile(groupMessagesFile, []);

function load(file) {
  return JSON.parse(fs.readFileSync(file));
}
function save(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------- MIDDLEWARE ----------
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json({ limit: "5mb" })); // limit increased so DataURL avatars work
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Session settings that work on local + Render (avoid secure:true when testing on HTTP)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // if you use HTTPS set NODE_ENV=production
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 días
    },
  })
);

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

// ---------- AUTH ----------
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Missing username or password" });

  let users = load(usersFile);
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ error: "Username already exists" });
  }

  const hash = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now(),
    username,
    password_hash: hash,
    contacts: [],
    online: false,
    avatar: null, // dataURL string or null
    description: "",
  };
  users.push(user);
  save(usersFile, users);

  req.session.user = { id: user.id, username: user.username };
  res.json(req.session.user);
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Missing username or password" });

  const users = load(usersFile);
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  req.session.user = { id: user.id, username: user.username };
  res.json(req.session.user);
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session || !req.session.user) return res.json({ user: null });
  const users = load(usersFile);
  const u = users.find((x) => x.id === req.session.user.id);
  if (!u) return res.json({ user: null });
  const { password_hash, ...safe } = u;
  res.json({ user: safe });
});

// ---------- PROFILE: avatar & description ----------
app.post("/api/me/profile", requireAuth, (req, res) => {
  // Expects { avatar: "<dataURL>" } and/or { description: "..." }
  const { avatar, description } = req.body;
  let users = load(usersFile);
  const u = users.find((x) => x.id === req.session.user.id);
  if (!u) return res.status(404).json({ error: "User not found" });

  if (avatar) {
    // For simplicity we just store DataURL directly in JSON (fine for small images / demo)
    u.avatar = avatar;
  }
  if (description !== undefined) {
    u.description = description;
  }
  save(usersFile, users);
  const { password_hash, ...safe } = u;
  res.json({ ok: true, user: safe });
});

// ---------- CONTACTS ----------
app.post("/api/add-contact", requireAuth, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "Missing username" });

  let users = load(usersFile);
  let me = users.find((u) => u.id === req.session.user.id);
  let other = users.find((u) => u.username === username);

  if (!other) return res.status(400).json({ error: "No existe ese usuario" });
  if (me.contacts.includes(other.id))
    return res.status(400).json({ error: "Ya es tu contacto" });

  me.contacts.push(other.id);
  save(usersFile, users);

  res.json({ ok: true, contact: { id: other.id, username: other.username } });
});

app.get("/api/contacts", requireAuth, (req, res) => {
  let users = load(usersFile);
  let me = users.find((u) => u.id === req.session.user.id);
  if (!me) return res.status(404).json({ error: "User not found" });

  let contacts = users
    .filter((u) => me.contacts.includes(u.id))
    .map((u) => ({
      id: u.id,
      username: u.username,
      online: !!u.online,
      avatar: u.avatar || null,
      description: u.description || "",
    }));

  res.json(contacts);
});

// ---------- CHAT GLOBAL ----------
app.get("/api/messages", (req, res) => {
  const msgs = load(messagesFile);
  res.json(msgs.slice(-100));
});

app.post("/api/messages", requireAuth, (req, res) => {
  const text = req.body.text;
  if (!text) return res.status(400).json({ error: "Missing text" });

  const user = req.session.user;
  let msgs = load(messagesFile);

  const msg = {
    id: Date.now(),
    user_id: user.id,
    username: user.username,
    text,
    created_at: new Date().toISOString(),
  };

  msgs.push(msg);
  save(messagesFile, msgs);

  io.emit("message", msg);
  res.json(msg);
});

// ---------- CHATS PRIVADOS ----------
app.post("/api/private/send", requireAuth, (req, res) => {
  const { to, text } = req.body;
  if (!to || !text) return res.status(400).json({ error: "Missing to or text" });

  let msgs = load(privateMessagesFile);

  const msg = {
    id: Date.now(),
    from: req.session.user.id,
    to: parseInt(to),
    text,
    created_at: new Date().toISOString(),
  };

  msgs.push(msg);
  save(privateMessagesFile, msgs);

  // Emit to both rooms (pm-a-b and pm-b-a)
  io.to(`pm-${msg.from}-${msg.to}`).emit("private_message", msg);
  io.to(`pm-${msg.to}-${msg.from}`).emit("private_message", msg);

  res.json(msg);
});

app.get("/api/private/:withId", requireAuth, (req, res) => {
  const withId = parseInt(req.params.withId);
  let msgs = load(privateMessagesFile);

  let filtered = msgs.filter(
    (m) =>
      (m.from === req.session.user.id && m.to === withId) ||
      (m.from === withId && m.to === req.session.user.id)
  );

  res.json(filtered);
});

// ---------- GRUPOS ----------
app.post("/api/groups/create", requireAuth, (req, res) => {
  const { name, members } = req.body;
  if (!name) return res.status(400).json({ error: "Name required" });

  let groups = load(groupsFile);

  const group = {
    id: Date.now(),
    name,
    members: Array.isArray(members) ? members.map(Number) : [],
  };

  // ensure creator is in members
  if (!group.members.includes(req.session.user.id)) group.members.push(req.session.user.id);

  groups.push(group);
  save(groupsFile, groups);

  res.json(group);
});

app.get("/api/groups", requireAuth, (req, res) => {
  let groups = load(groupsFile);
  const uid = req.session.user.id;

  const myGroups = groups.filter((g) => g.members.includes(uid));

  res.json(myGroups);
});

app.post("/api/groups/send", requireAuth, (req, res) => {
  const { group_id, text } = req.body;
  if (!group_id || !text) return res.status(400).json({ error: "Missing group_id or text" });

  let msgs = load(groupMessagesFile);

  const msg = {
    id: Date.now(),
    group_id,
    from: req.session.user.id,
    text,
    created_at: new Date().toISOString(),
  };

  msgs.push(msg);
  save(groupMessagesFile, msgs);

  io.to(`group-${group_id}`).emit("group_message", msg);

  res.json(msg);
});

app.get("/api/groups/messages/:id", requireAuth, (req, res) => {
  const gid = parseInt(req.params.id);
  let msgs = load(groupMessagesFile);

  res.json(msgs.filter((m) => m.group_id === gid));
});

// ---------- SOCKET.IO — PRESENCIA ----------
/*
 We'll maintain a map socketId -> userId so on disconnect we can mark offline.
*/
const socketUser = new Map(); // socket.id => userId

io.on("connection", (socket) => {
  // client emits 'online' after login with userId
  socket.on("online", (userId) => {
    try {
      userId = Number(userId);
      // store mapping
      socketUser.set(socket.id, userId);
      // mark user online
      let users = load(usersFile);
      const u = users.find((x) => x.id === userId);
      if (u) {
        u.online = true;
        save(usersFile, users);
      }
      io.emit("presence_update", { id: userId, online: true });
    } catch (e) {
      console.error("online handler error", e);
    }
  });

  socket.on("join_private", ({ me, other }) => {
    socket.join(`pm-${me}-${other}`);
    socket.join(`pm-${other}-${me}`);
  });

  socket.on("join_group", (groupId) => {
    socket.join(`group-${groupId}`);
  });

  socket.on("disconnect", () => {
    // mark user offline if we know it
    const uid = socketUser.get(socket.id);
    if (uid) {
      socketUser.delete(socket.id);
      // Check if any other socket still belongs to uid (user may have multiple tabs)
      const stillConnected = Array.from(socketUser.values()).some((v) => v === uid);
      if (!stillConnected) {
        let users = load(usersFile);
        const u = users.find((x) => x.id === uid);
        if (u) {
          u.online = false;
          save(usersFile, users);
        }
        io.emit("presence_update", { id: uid, online: false });
      }
    }
  });
});

// ---------- SPA support ----------
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------- START ----------
server.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
