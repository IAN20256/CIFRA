-- Cifra · base de datos D1 / D1 database schema
-- npx wrangler d1 execute cifra-db --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
  code      TEXT PRIMARY KEY,          -- código de 5 dígitos / 5-digit code
  name      TEXT NOT NULL DEFAULT '',  -- apodo opcional / optional nickname
  salt      TEXT NOT NULL,
  iter      INTEGER NOT NULL,
  verifier  TEXT NOT NULL,             -- HMAC(PEPPER, prueba derivada de la contraseña)
  pub       TEXT NOT NULL,             -- llave pública ECDH P-256
  enc_priv  TEXT NOT NULL,             -- llave privada cifrada con tu contraseña (y luego con el servidor)
  deleted   INTEGER NOT NULL DEFAULT 0,
  at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token     TEXT PRIMARY KEY,          -- SHA-256 del token
  code      TEXT NOT NULL,
  at        INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_code ON sessions(code);

CREATE TABLE IF NOT EXISTS rooms (
  id         TEXT PRIMARY KEY,         -- 'd:12345:67890' (privado) o 'g:<hash>' (grupo)
  kind       TEXT NOT NULL,            -- 'dm' | 'group'
  meta       TEXT NOT NULL DEFAULT '', -- nombre del grupo, cifrado
  ttl        INTEGER NOT NULL DEFAULT 0,
  stealth    INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
  room    TEXT NOT NULL,
  code    TEXT NOT NULL,
  secret  TEXT NOT NULL DEFAULT '',    -- llave del grupo, cifrada para este miembro
  read_id INTEGER NOT NULL DEFAULT 0,
  cleared INTEGER NOT NULL DEFAULT 0,
  at      INTEGER NOT NULL,
  PRIMARY KEY (room, code)
);
CREATE INDEX IF NOT EXISTS idx_members_code ON members(code);

CREATE TABLE IF NOT EXISTS messages (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  rev    INTEGER NOT NULL,
  room   TEXT NOT NULL,
  sender TEXT NOT NULL,
  kind   TEXT NOT NULL,                -- 'msg' | 'once' | 'sys' | 'del'
  body   TEXT NOT NULL DEFAULT '',     -- texto cifrado / ciphertext
  at     INTEGER NOT NULL,
  exp    INTEGER                       -- mensajes temporales / disappearing
);
CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room, id);
CREATE INDEX IF NOT EXISTS idx_messages_rev ON messages(rev);
CREATE INDEX IF NOT EXISTS idx_messages_exp ON messages(exp) WHERE exp IS NOT NULL;

CREATE TABLE IF NOT EXISTS opens (
  msg  INTEGER NOT NULL,
  code TEXT NOT NULL,
  at   INTEGER NOT NULL,
  PRIMARY KEY (msg, code)
);

CREATE TABLE IF NOT EXISTS blocks (
  code    TEXT NOT NULL,
  blocked TEXT NOT NULL,
  PRIMARY KEY (code, blocked)
);

CREATE TABLE IF NOT EXISTS attempts (
  key      TEXT PRIMARY KEY,
  n        INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS counters (
  k TEXT PRIMARY KEY,
  v INTEGER NOT NULL
);
INSERT OR IGNORE INTO counters (k, v) VALUES ('rev', 0);
