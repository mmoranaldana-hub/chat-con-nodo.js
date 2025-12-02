const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const path = require("path");

app.use(express.json());
app.use(express.static("public"));

app.use(
    session({
        secret: "super-secret",
        resave: false,
        saveUninitialized: false,
        store: new SQLiteStore()
    })
);

const db = new sqlite3.Database("./database.db");

db.serialize(() => {

    db.run(`CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        avatar TEXT,
        description TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS contacts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        contact_id INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS groups(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        owner_id INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS group_members(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        user_id INTEGER,
        is_admin INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        group_id INTEGER,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS presence(
        user_id INTEGER PRIMARY KEY,
        online INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});


// ----------------------------
//  RUTAS DE AUTENTICACIÓN
// ----------------------------

app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO users(username, password) VALUES(?, ?)`,
        [username, hash],
        function (err) {
            if (err) return res.json({ error: "El usuario ya existe" });

            req.session.userId = this.lastID;
            req.session.username = username;

            res.json({ ok: true, id: this.lastID });
        }
    );
});

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        async (err, user) => {
            if (!user) return res.json({ error: "Usuario no encontrado" });

            const valid = await bcrypt.compare(password, user.password);
            if (!valid) return res.json({ error: "Contraseña incorrecta" });

            req.session.userId = user.id;
            req.session.username = user.username;

            db.run(`INSERT OR REPLACE INTO presence(user_id, online) VALUES(?, 1)`,
                [user.id]
            );

            res.json({ ok: true, id: user.id });
        }
    );
});

app.post("/api/logout", (req, res) => {
    const uid = req.session.userId;

    db.run(`UPDATE presence SET online = 0 WHERE user_id = ?`, [uid]);
    req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
    if (!req.session.userId) return res.json({ user: null });

    db.get(
        `SELECT id, username, avatar, description
         FROM users
         WHERE id = ?`,
        [req.session.userId],
        (err, row) => res.json({ user: row })
    );
});


// ----------------------------
//  CONTACTOS
// ----------------------------

app.get("/api/contacts", (req, res) => {
    const uid = req.session.userId;

    db.all(
        `
        SELECT u.id, u.username, p.online
        FROM contacts c
        JOIN users u ON u.id = c.contact_id
        LEFT JOIN presence p ON p.user_id = u.id
        WHERE c.user_id = ?
        `,
        [uid],
        (err, rows) => res.json(rows || [])
    );
});

app.post("/api/add-contact", (req, res) => {
    const uid = req.session.userId;
    const { to } = req.body;

    db.get(`SELECT id FROM users WHERE username = ?`, [to], (err, user) => {
        if (!user) return res.json({ error: "El usuario no existe" });

        db.run(
            `INSERT OR IGNORE INTO contacts(user_id, contact_id)
             VALUES (?, ?)`,
            [uid, user.id],
            () => {
                io.emit("friend_request", { toId: user.id, fromName: req.session.username });
                res.json({ ok: true });
            }
        );
    });
});


// ----------------------------
//  GRUPOS
// ----------------------------

app.post("/api/groups/create", (req, res) => {
    const owner = req.session.userId;
    const { name, members } = req.body;

    db.run(
        `INSERT INTO groups(name, owner_id) VALUES(?, ?)`,
        [name, owner],
        function () {
            const groupId = this.lastID;

            db.run(
                `INSERT INTO group_members(group_id, user_id, is_admin)
                 VALUES(?, ?, 1)`,
                [groupId, owner]
            );

            (members || []).forEach(m => {
                db.run(
                    `INSERT INTO group_members(group_id, user_id, is_admin)
                     VALUES(?, ?, 0)`,
                    [groupId, m]
                );
            });

            res.json({ ok: true, groupId });
        }
    );
});

app.get("/api/groups", (req, res) => {
    const uid = req.session.userId;

    db.all(
        `
        SELECT g.id, g.name
        FROM group_members gm
        JOIN groups g ON g.id = gm.group_id
        WHERE gm.user_id = ?
        `,
        [uid],
        async (err, groups) => {
            for (let g of groups) {
                g.members = await new Promise(resolve => {
                    db.all(
                        `
                        SELECT u.id, u.username, gm.is_admin
                        FROM group_members gm
                        JOIN users u ON u.id = gm.user_id
                        WHERE gm.group_id = ?
                        `,
                        [g.id],
                        (err2, rows) => resolve(rows || [])
                    );
                });
            }

            res.json(groups);
        }
    );
});

app.get("/api/groups/messages/:id", (req, res) => {
    db.all(
        `
        SELECT m.*, u.username
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.group_id = ?
        ORDER BY m.timestamp ASC
        `,
        [req.params.id],
        (err, rows) => res.json(rows || [])
    );
});

app.post("/api/groups/send", (req, res) => {
    const uid = req.session.userId;
    const { group_id, text } = req.body;

    db.run(
        `
        INSERT INTO messages(sender_id, group_id, message)
        VALUES (?, ?, ?)
        `,
        [uid, group_id, text],
        () => {
            io.to("group_" + group_id).emit("group_message", {
                from: uid,
                group_id,
                text
            });

            res.json({ ok: true });
        }
    );
});

app.post("/api/groups/promote", (req, res) => {
    const uid = req.session.userId;
    const { groupId, targetId } = req.body;

    db.get(
        `
        SELECT is_admin FROM group_members
        WHERE user_id = ? AND group_id = ?
        `,
        [uid, groupId],
        (err, row) => {
            if (!row || !row.is_admin)
                return res.json({ error: "No eres administrador" });

            db.run(
                `
                UPDATE group_members
                SET is_admin = 1
                WHERE user_id = ? AND group_id = ?
                `,
                [targetId, groupId],
                () => res.json({ ok: true })
            );
        }
    );
});


// ----------------------------
// SOCKET.IO
// ----------------------------

io.on("connection", (socket) => {

    socket.on("auth", ({ userId }) => {
        socket.join("user_" + userId);
    });

    socket.on("join_group", (groupId) => {
        socket.join("group_" + groupId);
    });

    socket.on("private_message", (data) => {
        io.to("user_" + data.receiver).emit("private_message", data);
    });
});


http.listen(3000, () => console.log("Servidor listo en http://localhost:3000"));
