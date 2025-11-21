const express = require("express");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs"); // <--- CORREGIDO
const session = require("express-session");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Railway usa process.env.PORT siempre
const PORT = process.env.PORT || 8080;

// ---------- JSON DATABASE (NO SQLITE) ----------
const dataDir = path.join(__dirname, "data");
const usersFile = path.join(dataDir, "users.json");
const messagesFile = path.join(dataDir, "messages.json");

// Create folder if missing
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

// Initialize files
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, "[]");
if (!fs.existsSync(messagesFile)) fs.writeFileSync(messagesFile, "[]");

function loadUsers() {
  return JSON.parse(fs.readFileSync(usersFile));
}
function saveUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function loadMessages() {
  return JSON.parse(fs.readFileSync(messagesFile));
}
function saveMessages(msgs) {
  fs.writeFileSync(messagesFile, JSON.stringify(msgs, null, 2));
}

// ---------- MIDDLEWARE ----------
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: true,
  })
);

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

// ---------- AUTH ----------
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  let users = loadUsers();

  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ error: "Username already exists" });
  }

  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), username, password_hash: hash };
  users.push(user);
  saveUsers(users);

  req.session.user = { id: user.id, username: user.username };
  res.json(req.session.user);
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  req.session.user = { id: user.id, username: user.username };
  res.json(req.session.user);
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  if (req.session.user) return res.json({ user: req.session.user });
  res.json({ user: null });
});

// ---------- MESSAGES ----------
app.get("/api/messages", (req, res) => {
  const msgs = loadMessages();
  res.json(msgs.slice(-100));
});

app.post("/api/messages", requireAuth, (req, res) => {
  const text = req.body.text;
  if (!text) return res.status(400).json({ error: "Missing text" });

  const user = req.session.user;
  let msgs = loadMessages();

  const msg = {
    id: Date.now(),
    user_id: user.id,
    username: user.username,
    text,
    created_at: new Date().toISOString(),
  };

  msgs.push(msg);
  saveMessages(msgs);

  io.emit("message", msg);
  res.json(msg);
});

// SPA support
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------- SOCKETS ----------
io.on("connection", (socket) => {
  console.log("client connected");
});

// ---------- START ----------
server.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
