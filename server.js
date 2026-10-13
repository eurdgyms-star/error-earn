require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET || "";
if (isProduction && sessionSecret.length < 32) {
  throw new Error("Set SESSION_SECRET to a random value of at least 32 characters in production.");
}
if (!isProduction && sessionSecret.length < 32) {
  console.warn("WARNING: Set a long random SESSION_SECRET in .env before deployment.");
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "error-earn.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active','Blocked')),
 balance REAL NOT NULL DEFAULT 0 CHECK(balance >= 0),
 referral_code TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 reward REAL NOT NULL CHECK(reward >= 0),
 status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active','Paused')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS task_completions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 task_id INTEGER NOT NULL REFERENCES tasks(id),
 reward REAL NOT NULL,
 completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(user_id, task_id)
);
CREATE TABLE IF NOT EXISTS withdrawals (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 method TEXT NOT NULL CHECK(method IN ('bKash','Nagad')),
 amount REAL NOT NULL CHECK(amount >= 200),
 payment_account TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Approved','Rejected')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS admin_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 message TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const seedTasks = db.prepare("SELECT COUNT(*) AS n FROM tasks").get().n;
if (!seedTasks) {
  const insert = db.prepare("INSERT INTO tasks(title,description,reward,status) VALUES(?,?,?,'Active')");
  insert.run("Daily Check-in", "Check in once daily.", 5);
  insert.run("Learning Task", "Read the learning card.", 10);
  insert.run("Invite a Friend", "Invite friends using your referral code.", 15);
}
function log(message) {
  db.prepare("INSERT INTO admin_logs(message) VALUES(?)").run(String(message).slice(0, 240));
}
function safeUser(row) {
  if (!row) return null;
  return { id: row.id, username: row.username, email: row.email, status: row.status, balance: row.balance, referralCode: row.referral_code, createdAt: row.created_at };
}
function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Please log in first." });
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId);
  if (!user || user.status !== "Active") {
    req.session.destroy(() => {});
    return res.status(401).json({ error: "Account unavailable. Contact support." });
  }
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (req.session.admin !== true) return res.status(401).json({ error: "Admin login required." });
  next();
}
function csrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const token = req.get("x-csrf-token");
  if (!req.session.csrfToken || !token || !crypto.timingSafeEqual(Buffer.from(String(token)), Buffer.from(String(req.session.csrfToken)))) {
    return res.status(403).json({ error: "Invalid security token. Refresh the page and try again." });
  }
  next();
}
function createCsrf(req, res, next) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.set("Cache-Control", "no-store");
  res.json({ csrfToken: req.session.csrfToken });
}
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: "Too many attempts. Try again later." } });

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  name: "error_earn.sid",
  secret: sessionSecret || "development-only-change-me-123456789",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: isProduction, maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("/api/csrf", createCsrf);

app.post("/api/auth/register", authLimiter, csrf, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3–24 letters, numbers or underscores." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 160) return res.status(400).json({ error: "Enter a valid email address." });
  if (password.length < 10 || password.length > 72) return res.status(400).json({ error: "Password must be 10–72 characters." });
  const hash = await bcrypt.hash(password, 12);
  const code = crypto.randomBytes(5).toString("hex").toUpperCase();
  try {
    const result = db.prepare("INSERT INTO users(username,email,password_hash,referral_code) VALUES(?,?,?,?)").run(username, email, hash, code);
    req.session.userId = Number(result.lastInsertRowid);
    req.session.admin = false;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    res.status(201).json({ user: safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid)), csrfToken: req.session.csrfToken });
  } catch (e) {
    if (String(e.code).startsWith("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "Username or email is already registered." });
    throw e;
  }
});
app.post("/api/auth/login", authLimiter, csrf, async (req, res) => {
  const login = String(req.body.login || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const row = db.prepare("SELECT * FROM users WHERE lower(username)=? OR lower(email)=?").get(login, login);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) return res.status(401).json({ error: "Invalid login details." });
  if (row.status !== "Active") return res.status(403).json({ error: "This account is blocked." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.userId = row.id;
    req.session.admin = false;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    res.json({ user: safeUser(row), csrfToken: req.session.csrfToken });
  });
});
app.post("/api/auth/logout", csrf, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get("/api/me", requireUser, (req, res) => res.json({ user: safeUser(req.user) }));
app.get("/api/tasks", (req, res) => {
  const userId = req.session.userId || 0;
  res.json({ tasks: db.prepare(`SELECT t.id,t.title,t.description,t.reward,t.status,
    EXISTS(SELECT 1 FROM task_completions c WHERE c.task_id=t.id AND c.user_id=?) AS completed
    FROM tasks t WHERE t.status='Active' ORDER BY t.id DESC`).all(userId) });
});
app.post("/api/tasks/:id/complete", requireUser, csrf, (req, res) => {
  const task = db.prepare("SELECT * FROM tasks WHERE id=? AND status='Active'").get(Number(req.params.id));
  if (!task) return res.status(404).json({ error: "Task not found or inactive." });
  const tx = db.transaction(() => {
    const completion = db.prepare("INSERT INTO task_completions(user_id,task_id,reward) VALUES(?,?,?)").run(req.user.id, task.id, task.reward);
    db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(task.reward, req.user.id);
    return completion.lastInsertRowid;
  });
  try { tx(); res.json({ ok: true, message: "Task completed.", balance: db.prepare("SELECT balance FROM users WHERE id=?").get(req.user.id).balance }); }
  catch (e) { if (String(e.code).startsWith("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "You have already completed this task." }); throw e; }
});
app.get("/api/wallet", requireUser, (req, res) => {
  res.json({
    user: safeUser(req.user),
    withdrawals: db.prepare("SELECT id,method,amount,status,created_at AS createdAt FROM withdrawals WHERE user_id=? ORDER BY id DESC").all(req.user.id)
  });
});
app.post("/api/withdrawals", requireUser, csrf, (req, res) => {
  const method = String(req.body.method || "");
  const amount = Number(req.body.amount);
  const paymentAccount = String(req.body.paymentAccount || "").trim();
  if (!["bKash", "Nagad"].includes(method)) return res.status(400).json({ error: "Choose bKash or Nagad." });
  if (!Number.isFinite(amount) || amount < 200 || amount > 100000 || Math.round(amount) !== amount) return res.status(400).json({ error: "Withdrawal must be a whole-taka amount between ৳200 and ৳100,000." });
  if (paymentAccount.length < 8 || paymentAccount.length > 30) return res.status(400).json({ error: "Enter a valid payment account number." });
  if (req.user.balance < amount) return res.status(400).json({ error: "Insufficient demo balance." });
  const tx = db.transaction(() => {
    db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(amount, req.user.id);
    db.prepare("INSERT INTO withdrawals(user_id,method,amount,payment_account) VALUES(?,?,?,?)").run(req.user.id, method, amount, paymentAccount);
  });
  tx();
  res.status(201).json({ ok: true, message: "Demo withdrawal request submitted. No payment will be sent." });
});

app.get("/api/admin/me", (req, res) => res.json({ authenticated: req.session.admin === true }));
app.post("/api/admin/login", authLimiter, csrf, async (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const expectedUser = process.env.ADMIN_USERNAME || "admin";
  const expectedPassword = process.env.ADMIN_PASSWORD || "";
  if (!expectedPassword || expectedPassword === "ChangeThis-Strong-Password-Now") {
    if (isProduction) return res.status(503).json({ error: "Set a unique ADMIN_PASSWORD in your deployment environment." });
  }
  const userOk = crypto.timingSafeEqual(Buffer.from(username.padEnd(128).slice(0,128)), Buffer.from(expectedUser.padEnd(128).slice(0,128)));
  const passOk = expectedPassword && password.length <= 256 ? await bcrypt.compare(password, await bcrypt.hash(expectedPassword, 12)) : false;
  if (!userOk || !passOk) return res.status(401).json({ error: "Invalid admin credentials. Check .env setup." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.admin = true;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    log("Admin signed in");
    res.json({ ok: true, csrfToken: req.session.csrfToken });
  });
});
app.post("/api/admin/logout", requireAdmin, csrf, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/admin/overview", requireAdmin, (req, res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) n FROM users").get().n,
    activeTasks: db.prepare("SELECT COUNT(*) n FROM tasks WHERE status='Active'").get().n,
    pendingWithdrawals: db.prepare("SELECT COUNT(*) n FROM withdrawals WHERE status='Pending'").get().n,
    totalBalance: db.prepare("SELECT COALESCE(SUM(balance),0) n FROM users").get().n,
    recentUsers: db.prepare("SELECT id,username,email,status,balance,created_at AS createdAt FROM users ORDER BY id DESC LIMIT 10").all(),
    recentWithdrawals: db.prepare("SELECT w.id,u.username,w.method,w.amount,w.status,w.created_at AS createdAt FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 10").all()
  });
});
app.get("/api/admin/users", requireAdmin, (req, res) => {
  res.json({ users: db.prepare("SELECT id,username,email,status,balance,created_at AS createdAt FROM users ORDER BY id DESC").all() });
});
app.patch("/api/admin/users/:id/status", requireAdmin, csrf, (req, res) => {
  const status = String(req.body.status || "");
  if (!["Active", "Blocked"].includes(status)) return res.status(400).json({ error: "Invalid status." });
  const result = db.prepare("UPDATE users SET status=? WHERE id=?").run(status, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: "User not found." });
  log(`User ${req.params.id} status changed to ${status}`);
  res.json({ ok: true });
});
app.get("/api/admin/tasks", requireAdmin, (req, res) => res.json({ tasks: db.prepare("SELECT * FROM tasks ORDER BY id DESC").all() }));
app.post("/api/admin/tasks", requireAdmin, csrf, (req, res) => {
  const title = String(req.body.title || "").trim(), description = String(req.body.description || "").trim(), reward = Number(req.body.reward);
  if (!title || title.length > 100 || !description || description.length > 500 || !Number.isFinite(reward) || reward < 0 || reward > 10000) return res.status(400).json({ error: "Enter a valid title, description and reward." });
  const result = db.prepare("INSERT INTO tasks(title,description,reward) VALUES(?,?,?)").run(title, description, reward);
  log(`Task ${result.lastInsertRowid} created`);
  res.status(201).json({ id: result.lastInsertRowid });
});
app.patch("/api/admin/tasks/:id/status", requireAdmin, csrf, (req, res) => {
  const status = String(req.body.status || "");
  if (!["Active", "Paused"].includes(status)) return res.status(400).json({ error: "Invalid task status." });
  const result = db.prepare("UPDATE tasks SET status=? WHERE id=?").run(status, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: "Task not found." });
  log(`Task ${req.params.id} set to ${status}`);
  res.json({ ok: true });
});
app.delete("/api/admin/tasks/:id", requireAdmin, csrf, (req, res) => {
  const id = Number(req.params.id);
  const used = db.prepare("SELECT COUNT(*) n FROM task_completions WHERE task_id=?").get(id).n;
  if (used) return res.status(409).json({ error: "This task has completion history and cannot be deleted; pause it instead." });
  const result = db.prepare("DELETE FROM tasks WHERE id=?").run(id);
  if (!result.changes) return res.status(404).json({ error: "Task not found." });
  log(`Task ${id} deleted`);
  res.json({ ok: true });
});
app.get("/api/admin/withdrawals", requireAdmin, (req, res) => res.json({ withdrawals: db.prepare("SELECT w.id,w.user_id AS userId,u.username,w.method,w.amount,w.payment_account AS paymentAccount,w.status,w.created_at AS createdAt FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC").all() }));
app.patch("/api/admin/withdrawals/:id", requireAdmin, csrf, (req, res) => {
  const status = String(req.body.status || "");
  if (!["Approved", "Rejected"].includes(status)) return res.status(400).json({ error: "Invalid decision." });
  const w = db.prepare("SELECT * FROM withdrawals WHERE id=?").get(Number(req.params.id));
  if (!w) return res.status(404).json({ error: "Request not found." });
  if (w.status !== "Pending") return res.status(409).json({ error: "Request has already been reviewed." });
  const tx = db.transaction(() => {
    db.prepare("UPDATE withdrawals SET status=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?").run(status, w.id);
    if (status === "Rejected") db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(w.amount, w.user_id);
  });
  tx();
  log(`Withdrawal ${w.id} marked ${status}`);
  res.json({ ok: true, note: "This records a decision only. No payment provider is connected." });
});
app.get("/api/admin/logs", requireAdmin, (req, res) => res.json({ logs: db.prepare("SELECT id,message,created_at AS createdAt FROM admin_logs ORDER BY id DESC LIMIT 100").all() }));

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Unexpected server error." });
});
app.listen(PORT, () => console.log(`Error Earn running at http://localhost:${PORT}`));
