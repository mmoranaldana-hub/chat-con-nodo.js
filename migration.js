
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./data/database.sqlite');

db.serialize(()=>{
  db.run("ALTER TABLE group_members ADD COLUMN is_admin INTEGER DEFAULT 0", (err)=>{
    if(err) console.log("Column already exists or error:", err.message);
    else console.log("Column is_admin added.");
  });
});
