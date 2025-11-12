import sqlite3 from "sqlite3";

const db = new sqlite3.Database("./visitors.db");

db.all("SELECT * FROM scans ORDER BY id DESC", (err, rows) => {
  if (err) console.error("Error reading DB:", err);
  else console.table(rows);
  db.close();
});
