const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const config = require('./config');

let db;

function initDatabase() {
  const dataDir = path.dirname(config.dbPath);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  db = new Database(config.dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id TEXT UNIQUE NOT NULL,
      client_secret TEXT,
      client_name TEXT NOT NULL,
      client_type TEXT NOT NULL CHECK(client_type IN ('public', 'confidential')),
      redirect_uris TEXT NOT NULL,
      grant_types TEXT NOT NULL,
      allowed_scopes TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sub TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS authorization_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      client_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      code_challenge_method TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_type TEXT NOT NULL CHECK(token_type IN ('access_token', 'refresh_token')),
      token_value TEXT UNIQUE NOT NULL,
      client_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      scope TEXT NOT NULL,
      expires_at INTEGER,
      revoked INTEGER DEFAULT 0,
      associated_refresh TEXT,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_tokens_value ON tokens(token_value);
    CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON authorization_codes(code);
  `);

  try {
    db.prepare('ALTER TABLE clients ADD COLUMN allowed_scopes TEXT').run();
  } catch (e) {
  }

  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount === 0) {
    const crypto = require('crypto');
    const passwordHash = crypto.createHash('sha256').update('password123').digest('hex');
    db.prepare(`
      INSERT INTO users (sub, username, password_hash, name, email)
      VALUES (?, ?, ?, ?, ?)
    `).run('user-001', 'alice', passwordHash, 'Alice Smith', 'alice@example.com');
    console.log('Default test user created: alice / password123');
  }

  return db;
}

function getDb() {
  if (!db) {
    initDatabase();
  }
  return db;
}

module.exports = { initDatabase, getDb };
