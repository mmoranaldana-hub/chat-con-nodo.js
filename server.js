
// Complete server.js - supports frontend features: profiles, friend requests, unread counts, groups, presence
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
const io = new Server(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 8080;

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const usersFile = path.join(dataDir, "users.json");
const messagesFile = path.join(dataDir, "messages.json");
const privateMessagesFile = path.join(dataDir, "private_messages.json");
const groupsFile = path.join(dataDir, "groups.json");
const groupMessagesFile = path.join(dataDir, "group_messages.json");
const friendReqFile = path.join(dataDir, "friend_requests.json");
const unreadFile = path.join(dataDir, "unread.json");

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
ensureFile(friendReqFile, []);
ensureFile(unreadFile, { global: {}, private: {}, groups: {} });

function load(file) {
  return JSON.parse(fs.readFileSync(file));
}
function save(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// map userId -> set of socket ids
const userSockets = new Map();

app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Sessions - kept simple for Render/local (not production hardened)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
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
  if (req.session.user) return next();
  res.status(401).json({ error: "Unauthorized" });
}

// ---------- AUTH ----------
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const users = load(usersFile);
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ error: "Username already exists" });
  }
  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), username, password_hash: hash, contacts: [], online: false, profile: {} };
  users.push(user);
  save(usersFile, users);
  req.session.user = { id: user.id, username: user.username };
  res.json(req.session.user);
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
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
  if (!req.session.user) return res.json({ user: null });
  const users = load(usersFile);
  const u = users.find((x) => x.id === req.session.user.id);
  if (!u) {
    return res.json({ user: null });
  }
  return res.json({ user: { id: u.id, username: u.username, profile: u.profile || {}, contacts: u.contacts || [], online: !!u.online } });
});

// ---------- PROFILE ----------
app.post("/api/me/profile", requireAuth, (req, res) => {
  const { avatar, about } = req.body;
  const users = load(usersFile);
  const u = users.find((x) => x.id === req.session.user.id);
  if (!u) return res.status(400).json({ error: "User not found" });
  u.profile = u.profile || {};
  if (typeof avatar === "string") u.profile.avatar = avatar;
  if (typeof about === "string") u.profile.about = about;
  save(usersFile, users);
  res.json({ ok: true, profile: u.profile });
});

// ---------- CONTACTS & FRIEND REQUESTS ----------
app.post("/api/friend/request", requireAuth, (req, res) => {
  const { username } = req.body;
  const users = load(usersFile);
  const other = users.find((u) => u.username === username);
  if (!other) return res.status(400).json({ error: "No existe ese usuario" });
  const me = users.find((u) => u.id === req.session.user.id);
  if (me.contacts.includes(other.id)) return res.status(400).json({ error: "Ya es tu contacto" });
  const fr = load(friendReqFile);
  const exists = fr.find(r => r.from === me.id && r.to === other.id && r.status === "pending");
  if (exists) return res.status(400).json({ error: "Solicitud ya enviada" });
  const reqObj = { id: Date.now(), from: me.id, to: other.id, status: "pending", created_at: new Date().toISOString() };
  fr.push(reqObj);
  save(friendReqFile, fr);
  // emit to recipient if online
  const sockets = userSockets.get(other.id) || new Set();
  for (const sid of sockets) io.to(sid).emit("friend_request", { to: other.id, from: { id: me.id, username: me.username } });
  res.json({ ok: true });
});

app.post("/api/friend/accept", requireAuth, (req, res) => {
  const { request_id } = req.body;
  const fr = load(friendReqFile);
  const r = fr.find(x => x.id === request_id && x.to === req.session.user.id);
  if (!r) return res.status(400).json({ error: "Solicitud no encontrada" });
  r.status = "accepted";
  save(friendReqFile, fr);
  // add to contacts
  const users = load(usersFile);
  const me = users.find(u => u.id === req.session.user.id);
  const other = users.find(u => u.id === r.from);
  if (!me.contacts.includes(other.id)) me.contacts.push(other.id);
  if (!other.contacts.includes(me.id)) other.contacts.push(me.id);
  save(usersFile, users);
  // notify
  const sockets = userSockets.get(other.id) || new Set();
  for (const sid of sockets) io.to(sid).emit("friend_accepted", { other: me.id });
  res.json({ ok: true });
});

app.post("/api/add-contact", requireAuth, (req, res) => {
  // kept for compatibility (direct add)
  const { username } = req.body;
  const users = load(usersFile);
  const other = users.find((u) => u.username === username);
  if (!other) return res.status(400).json({ error: "No existe ese usuario" });
  const me = users.find((u) => u.id === req.session.user.id);
  if (me.contacts.includes(other.id)) return res.status(400).json({ error: "Ya es tu contacto" });
  me.contacts.push(other.id);
  save(usersFile, users);
  res.json({ ok: true });
});

app.get("/api/contacts", requireAuth, (req, res) => {
  const users = load(usersFile);
  const me = users.find((u) => u.id === req.session.user.id);
  const contacts = users.filter(u => me.contacts.includes(u.id)).map(u => ({ id: u.id, username: u.username, online: !!u.online }));
  res.json(contacts);
});

// ---------- GLOBAL CHAT ----------
app.get("/api/messages", (req, res) => {
  const msgs = load(messagesFile);
  res.json(msgs.slice(-200));
});

app.post("/api/messages", requireAuth, (req, res) => {
  const text = req.body.text;
  if (!text) return res.status(400).json({ error: "Missing text" });
  const user = req.session.user;
  const msgs = load(messagesFile);
  const msg = { id: Date.now(), user_id: user.id, username: user.username, text, created_at: new Date().toISOString() };
  msgs.push(msg);
  save(messagesFile, msgs);
  // increment unread.global for all users except sender
  const unread = load(unreadFile);
  const users = load(usersFile);
  users.forEach(u => {
    if (u.id !== user.id) {
      unread.global[u.id] = (unread.global[u.id] || 0) + 1;
    }
  });
  save(unreadFile, unread);
  io.emit("message", msg);
  io.emit("unread_update");
  res.json(msg);
});

app.post("/api/messages/mark-read", requireAuth, (req, res) => {
  const uid = req.session.user.id;
  const unread = load(unreadFile);
  unread.global[uid] = 0;
  save(unreadFile, unread);
  res.json({ ok: true });
});

// ---------- PRIVATE CHAT ----------
app.post("/api/private/send", requireAuth, (req, res) => {
  const { to, text } = req.body;
  const msgs = load(privateMessagesFile);
  const msg = { id: Date.now(), from: req.session.user.id, to: parseInt(to), text, created_at: new Date().toISOString() };
  msgs.push(msg);
  save(privateMessagesFile, msgs);
  // increment unread for recipient
  const unread = load(unreadFile);
  unread.private[msg.to] = unread.private[msg.to] || {};
  unread.private[msg.to][req.session.user.id] = (unread.private[msg.to][req.session.user.id] || 0) + 1;
  save(unreadFile, unread);
  // emit to recipient rooms/sockets
  io.to(`pm-${msg.from}-${msg.to}`).emit("private_message", msg);
  io.to(`pm-${msg.to}-${msg.from}`).emit("private_message", msg);
  // also emit unread update
  io.emit("unread_update");
  res.json(msg);
});

app.post("/api/private/mark-read", requireAuth, (req, res) => {
  const withId = parseInt(req.body.withId);
  const uid = req.session.user.id;
  const unread = load(unreadFile);
  if (unread.private && unread.private[uid]) {
    unread.private[uid][withId] = 0;
    save(unreadFile, unread);
  }
  res.json({ ok: true });
});

app.get("/api/private/:withId", requireAuth, (req, res) => {
  const withId = parseInt(req.params.withId);
  const msgs = load(privateMessagesFile);
  const uid = req.session.user.id;
  const filtered = msgs.filter(m => (m.from === uid && m.to === withId) || (m.from === withId && m.to === uid));
  res.json(filtered);
});

// ---------- GROUPS ----------
app.post("/api/groups/create", requireAuth, (req, res) => {
  const { name, members } = req.body;
  const groups = load(groupsFile);
  const group = { id: Date.now(), name: name || "Grupo", members: [...(members||[]).map(Number), req.session.user.id] };
  groups.push(group);
  save(groupsFile, groups);
  res.json(group);
});

app.post("/api/groups/add-member", requireAuth, (req, res) => {
  const { group_id, member_id } = req.body;
  const groups = load(groupsFile);
  const g = groups.find(x => x.id === parseInt(group_id));
  if (!g) return res.status(400).json({ error: "Grupo no encontrado" });
  if (!g.members.includes(parseInt(member_id))) {
    g.members.push(parseInt(member_id));
    save(groupsFile, groups);
    // notify the added user
    const sockets = userSockets.get(parseInt(member_id)) || new Set();
    for (const sid of sockets) io.to(sid).emit("group_member_added", { group_id: g.id });
  }
  res.json({ ok: true });
});

app.get("/api/groups", requireAuth, (req, res) => {
  const groups = load(groupsFile);
  const uid = req.session.user.id;
  const myGroups = groups.filter(g => g.members.includes(uid));
  res.json(myGroups);
});

app.post("/api/groups/send", requireAuth, (req, res) => {
  const { group_id, text } = req.body;
  const msgs = load(groupMessagesFile);
  const msg = { id: Date.now(), group_id: parseInt(group_id), from: req.session.user.id, text, created_at: new Date().toISOString() };
  msgs.push(msg);
  save(groupMessagesFile, msgs);
  // increment unread for group members except sender
  const groups = load(groupsFile);
  const g = groups.find(x => x.id === parseInt(group_id));
  const unread = load(unreadFile);
  unread.groups[group_id] = unread.groups[group_id] || {};
  if (g) {
    g.members.forEach(m => {
      if (m !== req.session.user.id) {
        unread.groups[group_id][m] = (unread.groups[group_id][m] || 0) + 1;
      }
    });
  }
  save(unreadFile, unread);
  io.to(`group-${group_id}`).emit("group_message", msg);
  io.emit("unread_update");
  res.json(msg);
});

app.post("/api/groups/mark-read", requireAuth, (req, res) => {
  const gid = parseInt(req.body.group_id);
  const uid = req.session.user.id;
  const unread = load(unreadFile);
  if (unread.groups && unread.groups[gid]) {
    unread.groups[gid][uid] = 0;
    save(unreadFile, unread);
  }
  res.json({ ok: true });
});

app.get("/api/groups/messages/:id", requireAuth, (req, res) => {
  const gid = parseInt(req.params.id);
  const msgs = load(groupMessagesFile);
  res.json(msgs.filter(m => m.group_id === gid));
});

// ---------- UNREAD SUMMARY ----------
app.get("/api/unread", requireAuth, (req, res) => {
  const uid = req.session.user.id;
  const unread = load(unreadFile);
  const globalCount = unread.global[uid] || 0;
  const groupsCounts = {};
  if (unread.groups) {
    for (const gid in unread.groups) {
      groupsCounts[gid] = unread.groups[gid][uid] || 0;
    }
  }
  const priv = unread.private && unread.private[uid] ? unread.private[uid] : {};
  res.json({ global: globalCount, groups: groupsCounts, private: priv });
});

// ---------- SOCKETS & PRESENCE ----------
io.on("connection", (socket) => {
  // store mapping when client identifies
  socket.on("online", (userId) => {
    if (!userId) return;
    // add socket id to user's set
    const set = userSockets.get(userId) || new Set();
    set.add(socket.id);
    userSockets.set(userId, set);
    // mark user online in users.json
    const users = load(usersFile);
    const u = users.find(x => x.id === userId);
    if (u) { u.online = true; save(usersFile, users); }
    io.emit("presence_update", { id: userId, online: true });
    socket.userId = userId;
  });

  socket.on("join_private", ({ me, other }) => {
    socket.join(`pm-${me}-${other}`);
    socket.join(`pm-${other}-${me}`);
  });

  socket.on("join_group", (groupId) => {
    socket.join(`group-${groupId}`);
  });

  socket.on("disconnect", () => {
    const uid = socket.userId;
    if (uid) {
      const set = userSockets.get(uid);
      if (set) {
        set.delete(socket.id);
        if (set.size === 0) {
          userSockets.delete(uid);
          // mark offline
          const users = load(usersFile);
          const u = users.find(x => x.id === uid);
          if (u) { u.online = false; save(usersFile, users); }
          io.emit("presence_update", { id: uid, online: false });
        } else {
          userSockets.set(uid, set);
        }
      }
    }
  });
});

// SPA support
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

server.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
