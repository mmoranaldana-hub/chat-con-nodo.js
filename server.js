// =========================
//   IMPORTS Y CONFIG
// =========================
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(cors());

// =========================
//        SESIONES
// =========================
app.use(
  session({
    secret: "supersecret23",
    resave: false,
    saveUninitialized: false,
  })
);

// =========================
//     BASE DE DATOS
// =========================
const db = new sqlite3.Database("database.db");

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function (err, rows) {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// =========================
//   INICIALIZAR TABLAS
// =========================
async function initDb() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT UNIQUE,
      verify_code TEXT,
      verified INTEGER DEFAULT 0
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS contacts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      contact_id INTEGER
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER,
      receiver_id INTEGER,
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      admin_id INTEGER
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS group_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER,
      user_id INTEGER,
      role TEXT DEFAULT 'member'
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS group_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER,
      sender_id INTEGER,
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

initDb();

// =========================
//   CONFIG CORREO
// =========================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "TU_CORREO@gmail.com",
    pass: "TU_PASSWORD_APP",
  },
});

function enviarCodigo(correo, codigo) {
  return transporter.sendMail({
    from: "Chat App",
    to: correo,
    subject: "Código de verificación",
    html: `<h1>Tu código de verificación es: ${codigo}</h1>`,
  });
}

// =========================
//  REGISTRO CON VERIFICACIÓN
// =========================
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email)
      return res.status(400).json({ error: "Faltan datos" });

    const exists = await dbGet(
      "SELECT id FROM users WHERE username=? OR email=?",
      [username, email]
    );

    if (exists)
      return res.status(400).json({ error: "Usuario o correo ya registrado" });

    const password_hash = await bcrypt.hash(password, 10);

    const code = String(Math.floor(100000 + Math.random() * 900000));

    await enviarCodigo(email, code);

    await dbRun(
      `INSERT INTO users (username, password_hash, email, verify_code, verified)
       VALUES (?,?,?,?,0)`,
      [username, password_hash, email, code]
    );

    res.json({
      ok: true,
      msg: "Usuario creado. Revisa tu correo para verificar la cuenta.",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error de servidor" });
  }
});

// =========================
//   VERIFICAR CUENTA
// =========================
app.post("/api/verify", async (req, res) => {
  try {
    const { email, code } = req.body;

    const user = await dbGet(
      "SELECT * FROM users WHERE email=? AND verify_code=?",
      [email, code]
    );

    if (!user)
      return res.json({ ok: false, msg: "Código incorrecto o correo inválido" });

    await dbRun(
      "UPDATE users SET verified=1, verify_code=NULL WHERE id=?",
      [user.id]
    );

    res.json({ ok: true, msg: "Cuenta verificada correctamente" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error de servidor" });
  }
});

// =========================
//     LOGIN CON BLOQUEO
// =========================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await dbGet("SELECT * FROM users WHERE username=?", [username]);

    if (!user)
      return res.status(400).json({ error: "Credenciales incorrectas" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok)
      return res.status(400).json({ error: "Credenciales incorrectas" });

    if (!user.verified)
      return res.status(403).json({
        error: "Debes verificar tu correo antes de iniciar sesión",
      });

    req.session.user = { id: user.id, username: user.username };
    res.json(req.session.user);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error de servidor" });
  }
});

// =========================
//     CONTACTOS
// =========================
app.get("/api/contacts", async (req, res) => {
  try {
    const user = req.session.user;
    if (!user) return res.status(403).json({ error: "No autenticado" });

    const rows = await dbAll(
      `SELECT u.id, u.username 
       FROM contacts c
       JOIN users u ON c.contact_id = u.id
       WHERE c.user_id=?`,
      [user.id]
    );

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Error de servidor" });
  }
});

app.post("/api/addContact", async (req, res) => {
  try {
    const user = req.session.user;
    const { contact_username } = req.body;

    if (!user) return res.status(403).json({ error: "No autenticado" });

    const contact = await dbGet(
      "SELECT id FROM users WHERE username=?",
      [contact_username]
    );

    if (!contact)
      return res.status(400).json({ error: "Contacto no encontrado" });

    await dbRun(
      "INSERT INTO contacts (user_id, contact_id) VALUES (?,?)",
      [user.id, contact.id]
    );

    res.json({ ok: true, msg: "Contacto agregado" });
  } catch (e) {
    res.status(500).json({ error: "Error de servidor" });
  }
});

// =========================
//     MENSAJES PRIVADOS
// =========================
app.get("/api/messages/:id", async (req, res) => {
  try {
    const user = req.session.user;
    const other = req.params.id;

    if (!user) return res.status(403).json({ error: "No autenticado" });

    const msgs = await dbAll(
      `
      SELECT * FROM messages 
      WHERE (sender_id=? AND receiver_id=?) 
      OR (sender_id=? AND receiver_id=?)
      ORDER BY timestamp ASC
      `,
      [user.id, other, other, user.id]
    );

    res.json(msgs);
  } catch (err) {
    res.status(500).json({ error: "Error de servidor" });
  }
});

// =========================
//       SOCKET.IO
// =========================
io.on("connection", (socket) => {
  console.log("Cliente conectado");

  socket.on("privateMessage", async (data) => {
    const { sender_id, receiver_id, message } = data;

    await dbRun(
      `INSERT INTO messages (sender_id, receiver_id, message)
       VALUES (?,?,?)`,
      [sender_id, receiver_id, message]
    );

    io.emit("newMessage", data);
  });
});

// =========================
//  SERVIDOR INICIADO
// =========================
server.listen(3000, () => {
  console.log("Server ON en puerto 3000");
});
