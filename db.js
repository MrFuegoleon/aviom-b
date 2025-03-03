const mysql = require("mysql2/promise");
require("dotenv").config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: process.env.DB_PORT || 3305,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "aviom2025",
  database: process.env.DB_NAME || "aviom2025",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

async function findUserByUsername(username) {
  const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
    username,
  ]);
  return rows[0];
}
/*
const users = [
  {
    id: 1,
    project_name: "admin",
    project_id: "88b62020c9c946f4ab54d8d48f1bb470",
    username: "user",
    // Hash généré pour "password"
    password: "password",
  },
  {
    id: 2,
    project_name: "test",
    project_id: "9265e1402f49480f869d18e95619c164",
    username: "admin",
    // Hash généré pour "admin123"
    password: "admin",
  },
];

async function findUserByUsername(username) {
  // Simule une recherche dans une base de données en retournant la promesse résolue
  return users.find((u) => u.username === username);
}
*/
module.exports = { findUserByUsername, pool };
