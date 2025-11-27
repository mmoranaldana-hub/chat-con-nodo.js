// server.js
// Chat Nodo — servidor completo (JSON files, sockets, presencia, perfiles, unread, friend requests)
// Versión corregida: validaciones añadidas, emisiones adicionales, pequeñas mejoras.

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
const io = new Server(server, { /* defaults */ });

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, "data");

// ensure data dir
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// file paths
const usersFile = path.join(DATA_DIR, "users.json");
const messagesFile = path.join(DATA_DIR, "messages.json"); // global chat
const privateMessagesFile = path.join(DATA_DIR, "private_messages.json");
const groupsFile = path.join(DATA_DIR, "groups.json");
const groupMessagesFile = path.join(DATA_DIR, "group_messages.json");
const friendRequestsFile = path.join(DATA_DIR, "friend_requests.json");

// helper to create file
function ensureFile(file, defaultContent) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(defaultContent, null, 2));
}
ensureFile(usersFile, []);
ensureFile(messagesFile, []);
ensureFile(privateMessagesFile, []);
ensureFile(groupsFile, []);
ensureFile(groupMessagesFile, []);
ensureFile(friendRequestsFile, []);

// read/write helpers
function load(file) {
  try { return JSON.parse(fs.readFileSync(file)); }
  catch(e){ console.error("Failed to read", file, e); return []; }
}
function save(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
  catch(e){ console.error("Failed to write", file, e); }
}

// middleware
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json({limit: '2mb'})); // allow base64 avatars
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
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: "Unauthorized" });
}

// helper to get persistent user object from disk by session
function getPersistentUser(req) {
  if (!req.session || !req.session.user) return null;
  const users = load(usersFile);
  return users.find(u => u.id === req.session.user.id) || null;
}

// ---------- AUTH ----------
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing username/password" });

    const users = load(usersFile);
    if (users.find(u => u.username === username)) return res.status(400).json({ error: "Username already exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: Date.now(),
      username,
      password_hash: hash,
      contacts: [],
      online: false,
      avatar: null,
      description: "",
      sockets: 0
    };

    users.push(user);
    save(usersFile, users);

    req.session.user = { id: user.id, username: user.username };
    res.json(req.session.user);
  } catch (err) {
    console.error("Register error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing username/password" });

    const users = load(usersFile);
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    req.session.user = { id: user.id, username: user.username };
    res.json(req.session.user);
  } catch (err) {
    console.error("Login error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  const u = req.session.user || null;
  if (!u) return res.json({ user: null });
  const users = load(usersFile);
  const user = users.find(x => x.id === u.id);
  if (!user) return res.json({ user: null });
  const publicUser = {
    id: user.id, username: user.username,
    avatar: user.avatar || null,
    description: user.description || "",
    online: !!user.online
  };
  res.json({ user: publicUser });
});

// update profile: description, avatar (base64 data URL), display name optional
app.post("/api/me/profile", requireAuth, (req, res) => {
  try {
    const { description, avatar } = req.body || {};
    const users = load(usersFile);
    const user = users.find(x => x.id === req.session.user.id);
    if (!user) return res.status(400).json({ error: "User not found" });

    if (typeof description === "string") user.description = description;
    if (avatar === null) user.avatar = null;
    else if (typeof avatar === "string" && avatar.startsWith("data:")) user.avatar = avatar;

    save(usersFile, users);
    res.json({ ok: true, avatar: user.avatar, description: user.description });
  } catch (err) {
    console.error("Profile update error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- FRIEND REQUESTS ----------
app.post("/api/friend/request", requireAuth, (req, res) => {
  try {
    const { to } = req.body || {};
    if (!to) return res.status(400).json({ error: "Missing 'to' username" });

    const users = load(usersFile);
    const target = users.find(u => u.username === to);
    const me = users.find(u => u.id === req.session.user.id);
    if (!target) return res.status(400).json({ error: "User not found" });
    if (!me) return res.status(400).json({ error: "Authenticated user not found" });
    if (me.id === target.id) return res.status(400).json({ error: "Cannot add yourself" });
    if (me.contacts.includes(target.id)) return res.status(400).json({ error: "Already contact" });

    const requests = load(friendRequestsFile);
    const exist = requests.find(r => r.from === me.id && r.to === target.id);
    if (exist) return res.status(400).json({ error: "Request already sent" });

    const newReq = { id: Date.now(), from: me.id, to: target.id, created_at: new Date().toISOString() };
    requests.push(newReq);
    save(friendRequestsFile, requests);

    // notify via socket
    io.emit("friend_request", { fromId: me.id, fromName: me.username, toId: target.id });
    res.json({ ok: true });
  } catch (err) {
    console.error("Friend request error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/friend/requests", requireAuth, (req, res) => {
  const meId = req.session.user.id;
  const requests = load(friendRequestsFile).filter(r => r.to === meId);
  const users = load(usersFile);
  const detailed = requests.map(r => {
    const from = users.find(u => u.id === r.from);
    return { id: r.id, from: r.from, fromName: from ? from.username : "User" , created_at: r.created_at };
  });
  res.json(detailed);
});

app.post("/api/friend/accept", requireAuth, (req, res) => {
  try {
    const { requestId } = req.body || {};
    if (!requestId) return res.status(400).json({ error: "Missing requestId" });

    let requests = load(friendRequestsFile);
    const rIdx = requests.findIndex(r => r.id === requestId && r.to === req.session.user.id);
    if (rIdx === -1) return res.status(400).json({ error: "Request not found" });

    const reqObj = requests[rIdx];
    requests.splice(rIdx,1);
    save(friendRequestsFile, requests);

    const users = load(usersFile);
    const a = users.find(u => u.id === reqObj.from);
    const b = users.find(u => u.id === reqObj.to);
    if (a && !a.contacts.includes(b.id)) a.contacts.push(b.id);
    if (b && !b.contacts.includes(a.id)) b.contacts.push(a.id);
    save(usersFile, users);

    io.emit("friend_accepted", { from: reqObj.from, to: reqObj.to });
    res.json({ ok: true });
  } catch (err) {
    console.error("Friend accept error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- CONTACTS ----------
app.post("/api/add-contact", requireAuth, (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: "Missing username" });

    const users = load(usersFile);
    const me = users.find(u => u.id === req.session.user.id);
    const other = users.find(u => u.username === username);
    if (!me) return res.status(400).json({ error: "Authenticated user not found" });
    if (!other) return res.status(400).json({ error: "No existe ese usuario" });
    if (me.contacts.includes(other.id)) return res.status(400).json({ error: "Ya es tu contacto" });

    me.contacts.push(other.id);
    save(usersFile, users);

    // notify interested parties (optional)
    io.emit("contact_added", { by: me.id, contact: { id: other.id, username: other.username } });

    res.json({ ok: true });
  } catch (err) {
    console.error("Add contact error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/contacts", requireAuth, (req, res) => {
  const users = load(usersFile);
  const me = users.find(u => u.id === req.session.user.id);
  if (!me) return res.status(400).json([]);

  const contacts = users.filter(u => me.contacts.includes(u.id)).map(u => ({
    id: u.id, username: u.username, online: !!u.online, avatar: u.avatar || null, description: u.description || ""
  }));
  res.json(contacts);
});

// ---------- GLOBAL CHAT ----------
app.get("/api/messages", (req, res) => {
  const msgs = load(messagesFile);
  res.json(msgs.slice(-200));
});

app.post("/api/messages", requireAuth, (req, res) => {
  try {
    const text = (req.body && req.body.text) || "";
    if (!text) return res.status(400).json({ error: "Missing text" });

    const user = req.session.user;
    const msgs = load(messagesFile);
    const msg = {
      id: Date.now(),
      user_id: user.id,
      username: user.username,
      text,
      created_at: new Date().toISOString()
    };
    msgs.push(msg);
    save(messagesFile, msgs);
    io.emit("message", msg);
    res.json(msg);
  } catch (err) {
    console.error("Post global message error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- PRIVATE MESSAGES (with read_by) ----------
app.post("/api/private/send", requireAuth, (req, res) => {
  try {
    const { to, text } = req.body || {};
    if (!to || !text) return res.status(400).json({ error: "Missing to/text" });

    const toId = parseInt(to);
    const msgs = load(privateMessagesFile);
    const msg = {
      id: Date.now(),
      from: req.session.user.id,
      to: toId,
      text,
      created_at: new Date().toISOString(),
      read_by: [ req.session.user.id ] // sender has "read"
    };
    msgs.push(msg);
    save(privateMessagesFile, msgs);

    // emit to both users' rooms (rooms are joined by client)
    io.to(`pm-${msg.from}-${msg.to}`).emit("private_message", msg);
    io.to(`pm-${msg.to}-${msg.from}`).emit("private_message", msg);
    res.json(msg);
  } catch (err) {
    console.error("Private send error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/private/:withId", requireAuth, (req, res) => {
  try {
    const withId = parseInt(req.params.withId);
    let msgs = load(privateMessagesFile);

    const filtered = msgs.filter(m =>
      (m.from === req.session.user.id && m.to === withId) ||
      (m.from === withId && m.to === req.session.user.id)
    );

    // mark unread -> read for current user
    let changed = false;
    filtered.forEach(m => {
      if (!m.read_by) m.read_by = [];
      if (!m.read_by.includes(req.session.user.id)) {
        m.read_by.push(req.session.user.id);
        changed = true;
      }
    });
    if (changed) {
      const all = load(privateMessagesFile);
      filtered.forEach(f => {
        const idx = all.findIndex(x => x.id === f.id);
        if (idx !== -1) all[idx] = f;
      });
      save(privateMessagesFile, all);
    }

    res.json(filtered);
  } catch (err) {
    console.error("Get private messages error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/private/mark-read", requireAuth, (req, res) => {
  try {
    const { withId } = req.body || {};
    if (!withId) return res.status(400).json({ error: "Missing withId" });
    const myId = req.session.user.id;

    let msgs = load(privateMessagesFile);
    let changed = false;
    msgs.forEach(m => {
      if ((m.from === parseInt(withId) && m.to === myId) || (m.from === myId && m.to === parseInt(withId))) {
        if (!m.read_by) m.read_by = [];
        if (!m.read_by.includes(myId)) { m.read_by.push(myId); changed = true; }
      }
    });
    if (changed) save(privateMessagesFile, msgs);
    res.json({ ok: true });
  } catch (err) {
    console.error("Mark read error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- GROUPS ----------
app.post("/api/groups/create", requireAuth, (req, res) => {
  try {
    const { name, members } = req.body || {};
    if (!name) return res.status(400).json({ error: "Missing group name" });

    const groups = load(groupsFile);
    const group = {
      id: Date.now(),
      name,
      members: Array.isArray(members) ? members.map(Number) : [],
      created_by: req.session.user.id
    };
    // ensure creator is in members
    if (!group.members.includes(req.session.user.id)) group.members.push(req.session.user.id);

    groups.push(group);
    save(groupsFile, groups);

    // notify clients that a new group was created (optional)
    io.emit("group_created", group);

    res.json(group);
  } catch (err) {
    console.error("Create group error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// add member to group
app.post("/api/groups/add-member", requireAuth, (req, res) => {
  try {
    const { group_id, username } = req.body || {};
    if (!group_id || !username) return res.status(400).json({ error: "Missing group_id/username" });

    const groups = load(groupsFile);
    const users = load(usersFile);
    const g = groups.find(x => x.id === parseInt(group_id));
    if (!g) return res.status(400).json({ error: "Group not found" });

    if (!g.members.includes(req.session.user.id)) return res.status(403).json({ error: "Not a member" });

    const u = users.find(x => x.username === username);
    if (!u) return res.status(400).json({ error: "User not found" });
    if (!g.members.includes(u.id)) g.members.push(u.id);

    save(groupsFile, groups);
    io.to(`group-${g.id}`).emit("group_member_added", { group_id: g.id, user: { id: u.id, username: u.username } });
    res.json({ ok: true, group: g });
  } catch (err) {
    console.error("Add member error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/groups", requireAuth, (req, res) => {
  try {
    const groups = load(groupsFile);
    const uid = req.session.user.id;
    const my = groups.filter(g => g.members.includes(uid));
    res.json(my);
  } catch (err) {
    console.error("Get groups error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/groups/send", requireAuth, (req, res) => {
  try {
    const { group_id, text } = req.body || {};
    if (!group_id || !text) return res.status(400).json({ error: "Missing group_id/text" });

    const msgs = load(groupMessagesFile);
    const msg = {
      id: Date.now(),
      group_id: parseInt(group_id),
      from: req.session.user.id,
      text,
      created_at: new Date().toISOString(),
      read_by: [ req.session.user.id ]
    };
    msgs.push(msg);
    save(groupMessagesFile, msgs);

    io.to(`group-${group_id}`).emit("group_message", msg);
    res.json(msg);
  } catch (err) {
    console.error("Group send error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/groups/messages/:id", requireAuth, (req, res) => {
  try {
    const gid = parseInt(req.params.id);
    let msgs = load(groupMessagesFile);
    const filtered = msgs.filter(m => m.group_id === gid);
    let changed = false;
    filtered.forEach(m => {
      if (!m.read_by) m.read_by = [];
      if (!m.read_by.includes(req.session.user.id)) { m.read_by.push(req.session.user.id); changed = true; }
    });
    if (changed) {
      const all = load(groupMessagesFile);
      filtered.forEach(f => {
        const idx = all.findIndex(x => x.id === f.id);
        if (idx !== -1) all[idx] = f;
      });
      save(groupMessagesFile, all);
    }
    res.json(filtered);
  } catch (err) {
    console.error("Get group messages error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- UNREAD COUNTS ----------
app.get("/api/unread", requireAuth, (req, res) => {
  try {
    const myId = req.session.user.id;
    const priv = load(privateMessagesFile);
    const groups = load(groupMessagesFile);

    const privateCounts = {};
    priv.forEach(m => {
      const other = (m.from === myId) ? m.to : m.from;
      if (!privateCounts[other]) privateCounts[other] = 0;
      if (!m.read_by || !m.read_by.includes(myId)) {
        if (m.to === myId && !m.read_by.includes(myId)) privateCounts[other] += 1;
      }
    });

    const groupCounts = {};
    groups.forEach(m => {
      const gid = m.group_id;
      if (!groupCounts[gid]) groupCounts[gid] = 0;
      if (!m.read_by || !m.read_by.includes(myId)) {
        groupCounts[gid] += 1;
      }
    });

    res.json({ global: 0, private: privateCounts, groups: groupCounts });
  } catch (err) {
    console.error("Get unread error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- SOCKET.IO presence & rooms ----------
const socketToUser = new Map();      // socketId -> userId
const userSocketCount = new Map();   // userId -> number

io.on("connection", (socket) => {
  socket.on("online", (userId) => {
    if (!userId) return;
    socketToUser.set(socket.id, userId);
    const prev = userSocketCount.get(userId) || 0;
    userSocketCount.set(userId, prev + 1);

    // persistent mark online true
    const users = load(usersFile);
    const u = users.find(x => x.id === userId);
    if (u) { u.online = true; save(usersFile, users); }

    io.emit("presence_update", { id: userId, online: true });
  });

  socket.on("join_private", ({ me, other }) => {
    if (!me || !other) return;
    socket.join(`pm-${me}-${other}`);
    socket.join(`pm-${other}-${me}`);
  });

  socket.on("join_group", (groupId) => {
    if (typeof groupId === "undefined" || groupId === null) return;
    socket.join(`group-${groupId}`);
  });

  socket.on("disconnect", () => {
    const userId = socketToUser.get(socket.id);
    socketToUser.delete(socket.id);
    if (userId) {
      const prev = userSocketCount.get(userId) || 1;
      const next = Math.max(0, prev - 1);
      userSocketCount.set(userId, next);

      if (next === 0) {
        const users = load(usersFile);
        const u = users.find(x => x.id === userId);
        if (u) { u.online = false; save(usersFile, users); }
        io.emit("presence_update", { id: userId, online: false });
      }
    }
  });
});

// SPA support (serve index for any non-api routes)
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// start
server.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
