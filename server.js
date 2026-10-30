require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-only-change-this-secret-before-deployment";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeThisPassword123!";
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "student-connect.db"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    mobile TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    college TEXT NOT NULL,
    study_year TEXT NOT NULL,
    registration_status TEXT NOT NULL DEFAULT 'Submitted',
    mobile_verified INTEGER NOT NULL DEFAULT 0,
    email_verified INTEGER NOT NULL DEFAULT 0,
    email_activity TEXT NOT NULL DEFAULT 'Not sent',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS admins (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);
const adminExists = db.prepare("SELECT username FROM admins WHERE username = ?").get(ADMIN_USERNAME);
if (!adminExists) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO admins(username,password_hash) VALUES(?,?)").run(ADMIN_USERNAME, hash);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const registrationLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const colleges = [
  "Anna University",
  "SRM Institute of Science and Technology",
  "VIT Chennai",
  "Saveetha Engineering College",
  "Sri Sairam Engineering College",
  "Other"
];
const years = ["1", "2", "3", "4", "Graduated"];

function safeStudent(row) {
  return {
    id: row.id, full_name: row.full_name, mobile: row.mobile, email: row.email,
    college: row.college, study_year: row.study_year,
    registration_status: row.registration_status,
    mobile_verified: Boolean(row.mobile_verified),
    email_verified: Boolean(row.email_verified),
    email_activity: row.email_activity,
    created_at: row.created_at
  };
}
function hashToken(token) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(token).digest("hex");
}
function requireAdmin(req, res, next) {
  const token = req.cookies.sc_admin;
  if (!token) return res.status(401).json({ error: "Admin login required." });
  const tokenHash = hashToken(token);
  const session = db.prepare("SELECT username, expires_at FROM sessions WHERE token_hash = ?").get(tokenHash);
  if (!session || session.expires_at < Date.now()) {
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
    res.clearCookie("sc_admin");
    return res.status(401).json({ error: "Session expired. Please sign in again." });
  }
  req.admin = { username: session.username, tokenHash };
  next();
}

app.get("/api/health", (req, res) => res.json({ ok: true }));
app.get("/api/colleges", (req, res) => res.json({ colleges, years }));

app.post("/api/register", registrationLimiter, (req, res) => {
  const full_name = String(req.body.full_name || "").trim();
  const mobile = String(req.body.mobile || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const college = String(req.body.college || "").trim();
  const study_year = String(req.body.study_year || "").trim();

  if (full_name.length < 2 || full_name.length > 100) return res.status(400).json({ error: "Enter a name between 2 and 100 characters." });
  if (!/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({ error: "Enter a valid 10-digit Indian mobile number." });
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (!colleges.includes(college)) return res.status(400).json({ error: "Choose a college from the predefined list." });
  if (!years.includes(study_year)) return res.status(400).json({ error: "Choose a valid year of study." });

  try {
    const result = db.prepare(`
      INSERT INTO students(full_name,mobile,email,college,study_year,registration_status,mobile_verified,email_verified,email_activity)
      VALUES(?,?,?,?,?,'Submitted',0,0,'Not sent')
    `).run(full_name, mobile, email, college, study_year);
    res.status(201).json({ message: "Registration submitted successfully.", student_id: result.lastInsertRowid });
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) return res.status(409).json({ error: "This mobile number or email is already registered." });
    console.error(err);
    res.status(500).json({ error: "Unable to save registration. Please try again." });
  }
});

app.post("/api/admin/login", loginLimiter, (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const admin = db.prepare("SELECT username,password_hash FROM admins WHERE username = ?").get(username);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: "Invalid username or password." });
  }
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions(token_hash,username,expires_at) VALUES(?,?,?)")
    .run(hashToken(token), admin.username, Date.now() + 8 * 60 * 60 * 1000);
  res.cookie("sc_admin", token, {
    httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000, path: "/"
  });
  res.json({ message: "Signed in successfully.", username: admin.username });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(req.admin.tokenHash);
  res.clearCookie("sc_admin", { httpOnly: true, sameSite: "strict", path: "/" });
  res.json({ message: "Signed out." });
});

app.get("/api/admin/me", requireAdmin, (req, res) => res.json({ username: req.admin.username }));

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const total = db.prepare("SELECT COUNT(*) AS n FROM students").get().n;
  const mobileVerified = db.prepare("SELECT COUNT(*) AS n FROM students WHERE mobile_verified=1").get().n;
  const emailVerified = db.prepare("SELECT COUNT(*) AS n FROM students WHERE email_verified=1").get().n;
  const collegeCount = db.prepare("SELECT COUNT(DISTINCT college) AS n FROM students").get().n;
  const byCollege = db.prepare("SELECT college, COUNT(*) AS count FROM students GROUP BY college ORDER BY college").all();
  const byYear = db.prepare("SELECT study_year, COUNT(*) AS count FROM students GROUP BY study_year ORDER BY study_year").all();
  res.json({ total, mobileVerified, emailVerified, collegeCount, byCollege, byYear });
});

app.get("/api/admin/students", requireAdmin, (req, res) => {
  const college = String(req.query.college || "");
  const year = String(req.query.year || "");
  const search = String(req.query.search || "").trim().slice(0, 100);
  const page = Math.max(1, Number.parseInt(req.query.page || "1", 10) || 1);
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit || "20", 10) || 20));
  const where = [];
  const params = [];
  if (college && colleges.includes(college)) { where.push("college = ?"); params.push(college); }
  if (year && years.includes(year)) { where.push("study_year = ?"); params.push(year); }
  if (search) {
    where.push("(full_name LIKE ? OR email LIKE ? OR mobile LIKE ?)");
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const total = db.prepare(`SELECT COUNT(*) AS n FROM students ${clause}`).get(...params).n;
  const rows = db.prepare(`SELECT * FROM students ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, (page - 1) * limit);
  res.json({ students: rows.map(safeStudent), total, page, limit, pages: Math.max(1, Math.ceil(total / limit)) });
});

app.get("/api/admin/export.csv", requireAdmin, (req, res) => {
  const college = String(req.query.college || "");
  const year = String(req.query.year || "");
  const where = [];
  const params = [];
  if (college && colleges.includes(college)) { where.push("college = ?"); params.push(college); }
  if (year && years.includes(year)) { where.push("study_year = ?"); params.push(year); }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db.prepare(`SELECT * FROM students ${clause} ORDER BY id`).all(...params);
  const headers = ["student_id","full_name","mobile","email","college","study_year","registration_status","mobile_verified","email_verified","email_activity","created_at"];
  const escape = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const csv = [headers.join(","), ...rows.map(r => [
    r.id,r.full_name,r.mobile,r.email,r.college,r.study_year,r.registration_status,
    r.mobile_verified ? "Verified" : "Pending",r.email_verified ? "Verified" : "Pending",r.email_activity,r.created_at
  ].map(escape).join(","))].join("\r\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="student-connect-export.csv"');
  res.send("\uFEFF" + csv);
});

// Verification stays pending until a real OTP/email verification provider is configured.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Unexpected server error." });
});

app.listen(PORT, () => {
  console.log(`Student Connect running at http://localhost:${PORT}`);
  console.log(`Admin username: ${ADMIN_USERNAME}`);
  if (ADMIN_PASSWORD === "ChangeThisPassword123!") console.warn("Set a strong ADMIN_PASSWORD in .env before using beyond local testing.");
});
