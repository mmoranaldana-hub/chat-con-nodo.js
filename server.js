// ===============================================
// ===============   IMPORTS   ===================
// ===============================================
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

// ===============================================
// ========== BASE DE DATOS JSON =================
// ===============================================
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

// Crear archivos si no existen
ensureFile(usersFile, []);
ensureFile(messagesFile, []);
ensureFile(privateMessagesFile, []);
ensureFile(groupsFile, []);
ensureFile(groupMessagesFile, []);

// Funciones generales
function load(file) {
    return JSON.parse(fs.readFileSync(file));
}
function save(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ===============================================
// ================ MIDDLEWARE ===================
// ===============================================
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

function requireAuth(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ error: "Unauthorized" });
}

// ===============================================
// ================ AUTENTICACIÓN ===============
// ===============================================
app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;

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
        online: false
    };

    users.push(user);
    save(usersFile, users);

    req.session.user = { id: user.id, username: user.username };
    res.json(req.session.user);
});

app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    let users = load(usersFile);
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

// Usuario actual
app.get("/api/me", (req, res) => {
    res.json({ user: req.session.user || null });
});

// ===============================================
// ================ CONTACTOS ====================
// ===============================================

app.post("/api/add-contact", requireAuth, (req, res) => {
    const { username } = req.body;

    let users = load(usersFile);
    let me = users.find((u) => u.id === req.session.user.id);
    let other = users.find((u) => u.username === username);

    if (!other) return res.status(400).json({ error: "No existe ese usuario" });
    if (me.contacts.includes(other.id))
        return res.status(400).json({ error: "Ya es tu contacto" });

    me.contacts.push(other.id);
    save(usersFile, users);

    res.json({ ok: true, contact: other.username });
});

app.get("/api/contacts", requireAuth, (req, res) => {
    let users = load(usersFile);
    let me = users.find((u) => u.id === req.session.user.id);

    let contacts = users
        .filter((u) => me.contacts.includes(u.id))
        .map((u) => ({
            id: u.id,
            username: u.username,
            online: u.online
        }));

    res.json(contacts);
});

// ===============================================
// ============== CHATS PRIVADOS =================
// ===============================================

app.post("/api/private/send", requireAuth, (req, res) => {
    const { to, text } = req.body;

    let msgs = load(privateMessagesFile);

    const msg = {
        id: Date.now(),
        from: req.session.user.id,
        to: parseInt(to),
        text,
        created_at: new Date().toISOString()
    };

    msgs.push(msg);
    save(privateMessagesFile, msgs);

    const room = `pm-${msg.from}-${msg.to}`;
    io.to(room).emit("private_message", msg);

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

// ===============================================
// ================== GRUPOS ======================
// ===============================================

app.post("/api/groups/create", requireAuth, (req, res) => {
    const { name, members } = req.body;

    let groups = load(groupsFile);

    const group = {
        id: Date.now(),
        name,
        members: [...members.map(Number), req.session.user.id]
    };

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

    let msgs = load(groupMessagesFile);

    const msg = {
        id: Date.now(),
        group_id,
        from: req.session.user.id,
        text,
        created_at: new Date().toISOString()
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

// ===============================================
// ========== SOCKET.IO — PRESENCIA ===============
// ===============================================

io.on("connection", (socket) => {

    socket.on("online", (userId) => {
        let users = load(usersFile);
        let u = users.find((x) => x.id === userId);
        if (u) {
            u.online = true;
            save(usersFile, users);
        }
        io.emit("presence_update", { id: userId, online: true });
    });

    socket.on("join_private", ({ me, other }) => {
        socket.join(`pm-${me}-${other}`);
        socket.join(`pm-${other}-${me}`);
    });

    socket.on("join_group", (groupId) => {
        socket.join(`group-${groupId}`);
    });

    socket.on("disconnect", () => {
        // Aquí no sabemos cuál user es
    });
});

// ===============================================
// ================ SPA SUPPORT ==================
// ===============================================
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ===============================================
server.listen(PORT, () => {
    console.log("Server running on port", PORT);
});

