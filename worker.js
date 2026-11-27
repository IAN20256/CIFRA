/**
 * Cifra — servidor / server
 * Cloudflare Worker + D1 (datos) + Durable Object "Hub" (tiempo real por WebSocket)
 *
 * El servidor NUNCA ve mensajes ni contraseñas en claro:
 *  - La app deriva llaves de tu contraseña (PBKDF2 600k + HKDF) y solo envía una "prueba" (auth).
 *  - Aquí guardamos HMAC(PEPPER, auth): sin el secreto PEPPER no sirve para adivinar contraseñas.
 *  - Mensajes, nombres de grupo y llaves privadas llegan ya cifrados desde el teléfono.
 *  - Los códigos de grupo ni siquiera llegan: el id del grupo es un hash de código + contraseña.
 *
 * The server never sees plaintext messages or passwords. See README.md.
 */

// La app completa va empaquetada dentro del Worker como texto (regla "Text" en wrangler.toml).
// The whole app is bundled into the Worker as text ("Text" rule in wrangler.toml).
import APP_HTML from './index.html';

const CODE_MIN = 10000, CODE_SPAN = 90000;   // códigos de usuario de 5 dígitos
const SESSION_IDLE = 24 * 3600e3;            // la sesión caduca tras 24 h sin uso
const TTLS = [0, 300, 3600, 86400, 604800];  // mensajes temporales: off, 5 min, 1 h, 24 h, 7 días
const MAX_GROUP = 200;
const LOGIN_MAX = 5, LOGIN_WIN = 15 * 60e3;  // 5 intentos fallidos por código cada 15 min
const IP_MAX = 40, IP_WIN = 15 * 60e3;       // y 40 por IP
const JOIN_MAX = 15, JOIN_WIN = 10 * 60e3;   // intentos fallidos de unirse a grupos
const SIGNUP_MAX = 20, SIGNUP_WIN = 3600e3;  // cuentas nuevas por IP por hora
const PAGE = 50;

const HTML_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-cache',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "frame-ancestors 'none'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) {
      if ((req.method === 'GET' || req.method === 'HEAD') && (url.pathname === '/' || url.pathname === '/index.html')) {
        return new Response(req.method === 'HEAD' ? null : APP_HTML, { headers: HTML_HEADERS });
      }
      return new Response('Cifra ✓', { headers: { 'Content-Type': 'text/plain; charset=utf-8', ...CORS } });
    }
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const c = { req, env, ctx, url, now: Date.now(), ip: req.headers.get('CF-Connecting-IP') || 'local' };
    try {
      if (!env.DB) fail(500, 'no_database');
      if (!env.PEPPER || String(env.PEPPER).length < 16) fail(500, 'server_misconfigured');
      const route = ROUTES[req.method + ' ' + url.pathname];
      if (!route) fail(404, 'not_found');
      if (route.auth) {
        c.me = await authenticate(c, !!route.query);
        if (!c.me) fail(401, 'unauthorized');
      }
      if (req.method === 'POST') c.body = await readJson(req, route.max || 64 * 1024);
      return await route.fn(c);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.code, ...e.extra }, e.status);
      console.error('cifra', (e && e.stack) || e);
      return json({ error: 'server_error' }, 500);
    }
  },

  // Cron (wrangler.toml): borra mensajes temporales vencidos, sesiones viejas y salas vacías.
  async scheduled(_event, env) {
    await cleanup(env, Date.now());
  },
};

const ROUTES = {
  'GET /api/health': { fn: c => json({ ok: true, realtime: !!c.env.HUB }) },
  'POST /api/signup': { fn: signup },
  'GET /api/salt': { fn: getSalt },
  'POST /api/login': { fn: login },
  'POST /api/logout': { auth: true, fn: logout },
  'POST /api/logout-others': { auth: true, fn: logoutOthers },
  'POST /api/profile': { auth: true, fn: profile },
  'POST /api/password': { auth: true, fn: changePassword, max: 1024 * 1024 },
  'POST /api/delete-account': { auth: true, fn: deleteAccount },
  'GET /api/user': { auth: true, fn: getUser },
  'GET /api/rooms': { auth: true, fn: listRooms },
  'POST /api/dm': { auth: true, fn: openDm },
  'POST /api/group': { auth: true, fn: createGroup },
  'POST /api/join': { auth: true, fn: joinGroup },
  'POST /api/leave': { auth: true, fn: leave },
  'POST /api/clear': { auth: true, fn: clearChat },
  'POST /api/settings': { auth: true, fn: roomSettings },
  'POST /api/send': { auth: true, fn: send },
  'POST /api/unsend': { auth: true, fn: unsend },
  'POST /api/open': { auth: true, fn: openOnce },
  'POST /api/alert': { auth: true, fn: screenshotAlert },
  'POST /api/read': { auth: true, fn: markRead },
  'POST /api/block': { auth: true, fn: block },
  'GET /api/messages': { auth: true, fn: messages },
  'GET /api/sync': { auth: true, fn: sync },
  'GET /api/ws': { auth: true, query: true, fn: websocket },
};

/* ───────────────────────── cuentas / accounts ───────────────────────── */

async function signup(c) {
  const b = c.body;
  const name = cleanName(b.name);
  const iter = Number.isInteger(b.iter) ? b.iter : 0;
  if (!isB64(b.salt, 24, 24) || !isB64(b.auth, 44, 44) || !isB64(b.pub, 88, 88) || !isSealed(b.priv, 500)) fail(400, 'bad_input');
  if (iter < 100000 || iter > 5000000) fail(400, 'bad_input');
  try { await crypto.subtle.importKey('raw', unb64(b.pub), { name: 'ECDH', namedCurve: 'P-256' }, true, []); }
  catch { fail(400, 'bad_input'); }
  const key = 'su:' + c.ip;
  const wait = await limited(c, key, SIGNUP_MAX);
  if (wait) fail(429, 'rate_limited', { wait });
  await hit(c, key, SIGNUP_WIN);
  for (let i = 0; i < 40; i++) {
    const code = String(CODE_MIN + randInt(CODE_SPAN));
    const verifier = await makeVerifier(c.env, code, b.auth);
    const encPriv = await sealSrv(c.env, b.priv, 'priv:' + code);
    const r = await c.env.DB.prepare(
      'INSERT OR IGNORE INTO users (code, name, salt, iter, verifier, pub, enc_priv, deleted, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)'
    ).bind(code, name, b.salt, iter, verifier, b.pub, encPriv, c.now).run();
    if (r.meta.changes === 1) {
      const token = await newSession(c, code);
      return json({ code, token, me: { code, name, pub: b.pub } });
    }
  }
  fail(503, 'codes_exhausted');
}

async function getSalt(c) {
  const code = c.url.searchParams.get('code') || '';
  if (!isCode(code)) fail(400, 'bad_input');
  const u = await c.env.DB.prepare('SELECT salt, iter FROM users WHERE code = ? AND deleted = 0').bind(code).first();
  if (!u) fail(404, 'no_user');
  return json({ salt: u.salt, iter: u.iter });
}

async function login(c) {
  const { code, auth } = c.body;
  if (!isCode(code) || !isB64(auth, 44, 44)) fail(400, 'bad_input');
  await checkPassword(c, code, auth, 'bad_login', 401);
  const u = await c.env.DB.prepare('SELECT name, pub, enc_priv FROM users WHERE code = ?').bind(code).first();
  const token = await newSession(c, code);
  return json({ token, me: { code, name: u.name, pub: u.pub }, priv: await openSrv(c.env, u.enc_priv, 'priv:' + code) });
}

// Verifica la contraseña con límite de intentos. Lanza error si falla.
async function checkPassword(c, code, auth, errCode, status) {
  const kc = 'lg:' + code, ki = 'ip:' + c.ip;
  const wait = Math.max(await limited(c, kc, LOGIN_MAX), await limited(c, ki, IP_MAX));
  if (wait) fail(429, 'locked', { wait });
  const u = await c.env.DB.prepare('SELECT verifier FROM users WHERE code = ? AND deleted = 0').bind(code).first();
  const expected = await makeVerifier(c.env, code, auth);
  if (!u || !safeEqual(u.verifier, expected)) {
    const n = await hit(c, kc, LOGIN_WIN);
    await hit(c, ki, IP_WIN);
    const left = Math.max(0, LOGIN_MAX - n);
    if (left === 0) fail(429, 'locked', { wait: Math.ceil(LOGIN_WIN / 1000) });
    fail(status, errCode, { left });
  }
  await c.env.DB.prepare('DELETE FROM attempts WHERE key = ?').bind(kc).run();
}

async function logout(c) {
  await c.env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(c.th).run();
  return json({ ok: true });
}

async function logoutOthers(c) {
  const DB = c.env.DB;
  const { results } = await DB.prepare('SELECT token FROM sessions WHERE code = ? AND token != ?').bind(c.me.code, c.th).all();
  await DB.prepare('DELETE FROM sessions WHERE code = ? AND token != ?').bind(c.me.code, c.th).run();
  kick(c, results.map(r => 's:' + r.token.slice(0, 16)));
  return json({ ok: true, n: results.length });
}

async function profile(c) {
  const name = cleanName(c.body.name);
  await c.env.DB.prepare('UPDATE users SET name = ? WHERE code = ?').bind(name, c.me.code).run();
  push(c, await coMembers(c, c.me.code), { type: 'room' });
  return json({ ok: true, name });
}

async function changePassword(c) {
  const b = c.body, code = c.me.code, DB = c.env.DB;
  const iter = Number.isInteger(b.iter) ? b.iter : 0;
  if (!isB64(b.old, 44, 44) || !isB64(b.salt, 24, 24) || !isB64(b.auth, 44, 44) || !isSealed(b.priv, 500)) fail(400, 'bad_input');
  if (iter < 100000 || iter > 5000000 || !Array.isArray(b.secrets) || b.secrets.length > 1000) fail(400, 'bad_input');
  await checkPassword(c, code, b.old, 'bad_pass', 403);
  // Every group key must be re-wrapped with the new password, or it would become unreadable.
  const groups = (await DB.prepare("SELECT room FROM members WHERE code = ? AND room LIKE 'g:%'").bind(code).all()).results.map(r => r.room);
  const given = new Set(b.secrets.map(s => s && s.room));
  if (groups.length !== b.secrets.length || groups.some(g => !given.has(g))) fail(409, 'secrets_mismatch');
  const stmts = [
    DB.prepare('UPDATE users SET salt = ?, iter = ?, verifier = ?, enc_priv = ? WHERE code = ?')
      .bind(b.salt, iter, await makeVerifier(c.env, code, b.auth), await sealSrv(c.env, b.priv, 'priv:' + code), code),
  ];
  for (const s of b.secrets) {
    if (!isSealed(s.secret, 800)) fail(400, 'bad_input');
    stmts.push(DB.prepare('UPDATE members SET secret = ? WHERE room = ? AND code = ?')
      .bind(await sealSrv(c.env, s.secret, 'sec:' + s.room + ':' + code), s.room, code));
  }
  const { results } = await DB.prepare('SELECT token FROM sessions WHERE code = ? AND token != ?').bind(code, c.th).all();
  stmts.push(DB.prepare('DELETE FROM sessions WHERE code = ? AND token != ?').bind(code, c.th));
  await DB.batch(stmts);
  kick(c, results.map(r => 's:' + r.token.slice(0, 16)));
  return json({ ok: true });
}

async function deleteAccount(c) {
  const code = c.me.code, DB = c.env.DB;
  if (!isB64(c.body.auth, 44, 44)) fail(400, 'bad_input');
  await checkPassword(c, code, c.body.auth, 'bad_pass', 403);
  const notify = await coMembers(c, code);
  const dms = (await DB.prepare("SELECT room FROM members WHERE code = ? AND room LIKE 'd:%'").bind(code).all()).results.map(r => r.room);
  const list = JSON.stringify(dms);
  await DB.batch([
    // private chats disappear for both people
    DB.prepare('DELETE FROM opens WHERE msg IN (SELECT id FROM messages WHERE room IN (SELECT value FROM json_each(?1)))').bind(list),
    DB.prepare('DELETE FROM messages WHERE room IN (SELECT value FROM json_each(?1))').bind(list),
    DB.prepare('DELETE FROM members WHERE room IN (SELECT value FROM json_each(?1))').bind(list),
    DB.prepare('DELETE FROM rooms WHERE id IN (SELECT value FROM json_each(?1))').bind(list),
    // in groups, their messages become "deleted"
    DB.prepare("UPDATE counters SET v = v + 1 WHERE k = 'rev'"),
    DB.prepare("UPDATE messages SET kind = 'del', body = '', rev = (SELECT v FROM counters WHERE k = 'rev') WHERE sender = ?1 AND kind IN ('msg', 'once')").bind(code),
    DB.prepare('DELETE FROM members WHERE code = ?1').bind(code),
    DB.prepare('DELETE FROM opens WHERE code = ?1').bind(code),
    DB.prepare('DELETE FROM blocks WHERE code = ?1 OR blocked = ?1').bind(code),
    DB.prepare('DELETE FROM sessions WHERE code = ?1').bind(code),
    // the code stays reserved so nobody inherits old conversations
    DB.prepare("UPDATE users SET deleted = 1, name = '', salt = '', verifier = '', pub = '', enc_priv = '' WHERE code = ?1").bind(code),
  ]);
  await dropEmptyRooms(DB);
  push(c, notify.filter(x => x !== code), { type: 'room' });
  kick(c, ['u:' + code]);
  return json({ ok: true });
}

async function getUser(c) {
  const code = c.url.searchParams.get('code') || '';
  if (!isCode(code)) fail(400, 'bad_input');
  if (!memLimit('usr:' + c.me.code, 40, 60e3)) fail(429, 'rate_limited', { wait: 60 });
  const u = await c.env.DB.prepare('SELECT code, name, pub FROM users WHERE code = ? AND deleted = 0').bind(code).first();
  if (!u) fail(404, 'no_user');
  return json({ user: u });
}

/* ───────────────────────── salas / rooms ───────────────────────── */

// Columns for a message row as seen by user ?1. "Once" messages hide their ciphertext from the
// sender and from anyone who already opened them.
const MSG_COLS = `m.id, m.rev, m.room, m.sender, m.kind, m.at, m.exp,
  CASE WHEN m.kind = 'once' AND (m.sender = ?1 OR EXISTS (SELECT 1 FROM opens o WHERE o.msg = m.id AND o.code = ?1)) THEN '' ELSE m.body END AS body,
  CASE WHEN m.kind = 'once' THEN (SELECT COUNT(*) FROM opens o WHERE o.msg = m.id) ELSE 0 END AS seen,
  CASE WHEN m.kind = 'once' AND EXISTS (SELECT 1 FROM opens o WHERE o.msg = m.id AND o.code = ?1) THEN 1 ELSE 0 END AS opened`;

async function listRooms(c) {
  const me = c.me.code, DB = c.env.DB;
  const [rv, rs, bl] = await DB.batch([
    DB.prepare("SELECT v FROM counters WHERE k = 'rev'"),
    DB.prepare(`SELECT r.id, r.kind, r.meta, r.ttl, r.stealth, r.created_by, r.at, mb.secret,
        (SELECT COUNT(*) FROM messages m WHERE m.room = r.id AND m.id > MAX(mb.read_id, mb.cleared) AND m.sender != ?1
           AND m.kind IN ('msg', 'once') AND (m.exp IS NULL OR m.exp > ?2)) AS unread,
        (SELECT m.id FROM messages m WHERE m.room = r.id AND m.id > mb.cleared AND (m.exp IS NULL OR m.exp > ?2)
           ORDER BY m.id DESC LIMIT 1) AS last_id
      FROM members mb JOIN rooms r ON r.id = mb.room WHERE mb.code = ?1`).bind(me, c.now),
    DB.prepare('SELECT blocked FROM blocks WHERE code = ?').bind(me),
  ]);
  const list = rs.results;
  const lastIds = list.map(r => r.last_id).filter(Boolean);
  const peerOf = id => id.slice(2).split(':').find(x => x !== me) || me;
  const peers = [...new Set(list.filter(r => r.kind === 'dm').map(r => peerOf(r.id)))];
  const groups = list.filter(r => r.kind === 'group').map(r => r.id);
  const [lm, us, gm] = await DB.batch([
    DB.prepare(`SELECT ${MSG_COLS} FROM messages m WHERE m.id IN (SELECT value FROM json_each(?2))`).bind(me, JSON.stringify(lastIds)),
    DB.prepare('SELECT code, name, pub, deleted FROM users WHERE code IN (SELECT value FROM json_each(?1))').bind(JSON.stringify(peers)),
    DB.prepare(`SELECT mb.room, mb.code, u.name FROM members mb JOIN users u ON u.code = mb.code
      WHERE mb.room IN (SELECT value FROM json_each(?1)) ORDER BY mb.at`).bind(JSON.stringify(groups)),
  ]);
  const last = new Map(lm.results.map(m => [m.id, m]));
  const users = new Map(us.results.map(u => [u.code, u]));
  const members = new Map();
  for (const x of gm.results) {
    if (!members.has(x.room)) members.set(x.room, []);
    members.get(x.room).push({ code: x.code, name: x.name });
  }
  const rooms = [];
  for (const r of list) {
    const room = {
      id: r.id, kind: r.kind, meta: r.meta, ttl: r.ttl, stealth: r.stealth, by: r.created_by, at: r.at,
      unread: r.unread, last: (r.last_id && last.get(r.last_id)) || null,
    };
    if (r.kind === 'dm') {
      const u = users.get(peerOf(r.id));
      room.peer = u && !u.deleted ? { code: u.code, name: u.name, pub: u.pub } : { code: peerOf(r.id), name: '', pub: '', gone: true };
    } else {
      room.members = members.get(r.id) || [];
      try { room.secret = r.secret ? await openSrv(c.env, r.secret, 'sec:' + r.id + ':' + me) : ''; }
      catch { room.secret = ''; } // the app shows this group as unreadable instead of failing the whole list
    }
    rooms.push(room);
  }
  return json({ rev: rv.results[0].v, rooms, blocked: bl.results.map(x => x.blocked) });
}

async function openDm(c) {
  const peer = c.body.code, me = c.me.code, DB = c.env.DB;
  if (!isCode(peer)) fail(400, 'bad_input');
  if (peer === me) fail(400, 'self');
  if (!memLimit('dm:' + me, 30, 60e3)) fail(429, 'rate_limited', { wait: 60 });
  const u = await DB.prepare('SELECT code FROM users WHERE code = ? AND deleted = 0').bind(peer).first();
  if (!u) fail(404, 'no_user');
  const bl = (await DB.prepare('SELECT code FROM blocks WHERE (code = ?1 AND blocked = ?2) OR (code = ?2 AND blocked = ?1)').bind(me, peer).all()).results;
  if (bl.some(x => x.code === me)) fail(403, 'you_blocked');
  if (bl.some(x => x.code === peer)) fail(403, 'blocked');
  const id = dmId(me, peer);
  const addMember = `INSERT OR IGNORE INTO members (room, code, secret, read_id, cleared, at)
    VALUES (?1, ?2, '', 0, (SELECT COALESCE(MAX(id), 0) FROM messages WHERE room = ?1), ?3)`;
  await DB.batch([
    DB.prepare("INSERT OR IGNORE INTO rooms (id, kind, meta, ttl, stealth, created_by, at) VALUES (?1, 'dm', '', 0, 0, ?2, ?3)").bind(id, me, c.now),
    DB.prepare(addMember).bind(id, me, c.now),
    DB.prepare(addMember).bind(id, peer, c.now),
  ]);
  push(c, [me, peer], { type: 'room' });
  return json({ room: id });
}

async function createGroup(c) {
  const b = c.body, me = c.me.code, DB = c.env.DB;
  if (!isGroupId(b.id) || !isSealed(b.meta, 2000) || !isSealed(b.secret, 800)) fail(400, 'bad_input');
  const ttl = TTLS.includes(b.ttl) ? b.ttl : 0;
  const stealth = b.stealth ? 1 : 0;
  if (!memLimit('grp:' + me, 10, 60e3)) fail(429, 'rate_limited', { wait: 60 });
  const r = await DB.prepare("INSERT OR IGNORE INTO rooms (id, kind, meta, ttl, stealth, created_by, at) VALUES (?1, 'group', ?2, ?3, ?4, ?5, ?6)")
    .bind(b.id, b.meta, ttl, stealth, me, c.now).run();
  if (!r.meta.changes) fail(409, 'exists');
  await DB.prepare('INSERT INTO members (room, code, secret, read_id, cleared, at) VALUES (?, ?, ?, 0, 0, ?)')
    .bind(b.id, me, await sealSrv(c.env, b.secret, 'sec:' + b.id + ':' + me), c.now).run();
  await insertMsg(c, b.id, 'sys', JSON.stringify({ e: 'create' }), expFor(c, ttl));
  push(c, [me], { type: 'room' });
  return json({ room: b.id });
}

async function joinGroup(c) {
  const b = c.body, me = c.me.code, DB = c.env.DB;
  if (!isGroupId(b.id) || !isSealed(b.secret, 800)) fail(400, 'bad_input');
  const key = 'jn:' + me;
  const wait = await limited(c, key, JOIN_MAX);
  if (wait) fail(429, 'rate_limited', { wait });
  const room = await DB.prepare("SELECT id, ttl FROM rooms WHERE id = ? AND kind = 'group'").bind(b.id).first();
  if (!room) {
    await hit(c, key, JOIN_WIN);
    fail(404, 'bad_group');
  }
  const secret = await sealSrv(c.env, b.secret, 'sec:' + b.id + ':' + me);
  const already = await DB.prepare('SELECT code FROM members WHERE room = ? AND code = ?').bind(b.id, me).first();
  if (already) {
    await DB.prepare('UPDATE members SET secret = ? WHERE room = ? AND code = ?').bind(secret, b.id, me).run();
    return json({ room: b.id, already: true });
  }
  const n = (await DB.prepare('SELECT COUNT(*) AS n FROM members WHERE room = ?').bind(b.id).first()).n;
  if (n >= MAX_GROUP) fail(403, 'full');
  // New members only see messages sent after they joined.
  await DB.prepare(`INSERT INTO members (room, code, secret, read_id, cleared, at)
    VALUES (?1, ?2, ?3, 0, (SELECT COALESCE(MAX(id), 0) FROM messages WHERE room = ?1), ?4)`).bind(b.id, me, secret, c.now).run();
  const m = await insertMsg(c, b.id, 'sys', JSON.stringify({ e: 'join' }), expFor(c, room.ttl));
  push(c, await roomCodes(c, b.id), [{ type: 'msg', m }, { type: 'room' }]);
  return json({ room: b.id });
}

async function leave(c) {
  const room = c.body.room, me = c.me.code, DB = c.env.DB;
  if (!isRoomId(room)) fail(400, 'bad_input');
  const r = await member(c, room);
  await DB.prepare('DELETE FROM members WHERE room = ? AND code = ?').bind(room, me).run();
  const codes = await roomCodes(c, room);
  if (!codes.length) await deleteRoom(DB, room);
  else if (r.kind === 'group') {
    const m = await insertMsg(c, room, 'sys', JSON.stringify({ e: 'leave' }), expFor(c, r.ttl));
    push(c, codes, [{ type: 'msg', m }, { type: 'room' }]);
  }
  push(c, [me], { type: 'room' });
  return json({ ok: true });
}

async function clearChat(c) {
  const room = c.body.room;
  if (!isRoomId(room)) fail(400, 'bad_input');
  await member(c, room);
  await c.env.DB.prepare(`UPDATE members SET
      cleared = (SELECT COALESCE(MAX(id), 0) FROM messages WHERE room = ?1),
      read_id = (SELECT COALESCE(MAX(id), 0) FROM messages WHERE room = ?1)
    WHERE room = ?1 AND code = ?2`).bind(room, c.me.code).run();
  push(c, [c.me.code], { type: 'room' });
  return json({ ok: true });
}

// Ajustes del chat que aplican a TODOS sus miembros: mensajes temporales y modo sigilo.
async function roomSettings(c) {
  const b = c.body, DB = c.env.DB;
  if (!isRoomId(b.room)) fail(400, 'bad_input');
  const r = await member(c, b.room);
  const evs = [];
  let ttl = r.ttl;
  if (b.ttl !== undefined) {
    if (!TTLS.includes(b.ttl)) fail(400, 'bad_input');
    if (b.ttl !== r.ttl) {
      ttl = b.ttl;
      await DB.prepare('UPDATE rooms SET ttl = ? WHERE id = ?').bind(ttl, b.room).run();
      evs.push({ type: 'msg', m: await insertMsg(c, b.room, 'sys', JSON.stringify({ e: 'ttl', v: ttl }), expFor(c, ttl)) });
    }
  }
  if (b.stealth !== undefined) {
    const v = b.stealth ? 1 : 0;
    if (v !== r.stealth) {
      await DB.prepare('UPDATE rooms SET stealth = ? WHERE id = ?').bind(v, b.room).run();
      evs.push({ type: 'msg', m: await insertMsg(c, b.room, 'sys', JSON.stringify({ e: 'stealth', v }), expFor(c, ttl)) });
    }
  }
  if (evs.length) push(c, await roomCodes(c, b.room), [...evs, { type: 'room' }]);
  return json({ ok: true });
}

/* ───────────────────────── mensajes / messages ───────────────────────── */

async function send(c) {
  const { room, kind, body } = c.body, me = c.me.code, DB = c.env.DB;
  if (!isRoomId(room) || (kind !== 'msg' && kind !== 'once') || !isSealed(body, 30000)) fail(400, 'bad_input');
  if (!memLimit('snd:' + me, 40, 20e3)) fail(429, 'rate_limited', { wait: 20 });
  const r = await member(c, room);
  let codes, evs = [];
  if (r.kind === 'dm') {
    const peer = room.slice(2).split(':').find(x => x !== me);
    const bl = await DB.prepare('SELECT 1 AS x FROM blocks WHERE (code = ?1 AND blocked = ?2) OR (code = ?2 AND blocked = ?1) LIMIT 1').bind(me, peer).first();
    if (bl) fail(403, 'blocked');
    const pu = await DB.prepare('SELECT deleted FROM users WHERE code = ?').bind(peer).first();
    if (!pu || pu.deleted) fail(403, 'blocked');
    // If they deleted this chat, bring it back for them (without the old history).
    const back = await DB.prepare(`INSERT OR IGNORE INTO members (room, code, secret, read_id, cleared, at)
      VALUES (?1, ?2, '', 0, (SELECT COALESCE(MAX(id), 0) FROM messages WHERE room = ?1), ?3)`).bind(room, peer, c.now).run();
    if (back.meta.changes) evs.push({ type: 'room' });
    codes = [me, peer];
  } else {
    codes = await roomCodes(c, room);
  }
  const m = await insertMsg(c, room, kind, body, expFor(c, r.ttl));
  push(c, codes, [{ type: 'msg', m }, ...evs]);
  return json({ m });
}

async function unsend(c) {
  const id = Number.isInteger(c.body.id) ? c.body.id : 0, me = c.me.code, DB = c.env.DB;
  if (id <= 0) fail(400, 'bad_input');
  const [, up] = await DB.batch([
    DB.prepare("UPDATE counters SET v = v + 1 WHERE k = 'rev'"),
    DB.prepare(`UPDATE messages SET kind = 'del', body = '', rev = (SELECT v FROM counters WHERE k = 'rev')
      WHERE id = ?1 AND sender = ?2 AND kind IN ('msg', 'once') RETURNING id, rev, room, sender, kind, at, exp`).bind(id, me),
    DB.prepare("DELETE FROM opens WHERE msg = ?1 AND EXISTS (SELECT 1 FROM messages WHERE id = ?1 AND sender = ?2 AND kind = 'del')").bind(id, me),
  ]);
  if (!up.results.length) fail(404, 'not_found');
  const m = { ...up.results[0], body: '', seen: 0, opened: 0 };
  push(c, await roomCodes(c, m.room), { type: 'msg', m });
  return json({ m });
}

// "Ver una vez": se marca como abierto; cuando todos lo abrieron, el servidor borra el cifrado.
async function openOnce(c) {
  const id = Number.isInteger(c.body.id) ? c.body.id : 0, me = c.me.code, DB = c.env.DB;
  const m = await DB.prepare('SELECT m.id, m.room, m.sender, m.kind FROM messages m JOIN members mb ON mb.room = m.room AND mb.code = ?2 WHERE m.id = ?1')
    .bind(id, me).first();
  if (!m || m.kind !== 'once') fail(404, 'not_found');
  if (m.sender === me) fail(400, 'bad_input');
  const ins = await DB.prepare('INSERT OR IGNORE INTO opens (msg, code, at) VALUES (?, ?, ?)').bind(id, me, c.now).run();
  if (ins.meta.changes) {
    await DB.batch([
      DB.prepare("UPDATE counters SET v = v + 1 WHERE k = 'rev'"),
      DB.prepare("UPDATE messages SET rev = (SELECT v FROM counters WHERE k = 'rev') WHERE id = ?1").bind(id),
      DB.prepare(`UPDATE messages SET body = '' WHERE id = ?1
        AND (SELECT COUNT(*) FROM members WHERE room = ?2 AND code != ?3) <= (SELECT COUNT(*) FROM opens WHERE msg = ?1)`).bind(id, m.room, m.sender),
    ]);
  }
  const seen = (await DB.prepare('SELECT COUNT(*) AS n FROM opens WHERE msg = ?').bind(id).first()).n;
  push(c, await roomCodes(c, m.room), { type: 'open', id, room: m.room, by: me, seen });
  return json({ ok: true, seen });
}

async function screenshotAlert(c) {
  const room = c.body.room;
  if (!isRoomId(room)) fail(400, 'bad_input');
  if (!memLimit('alr:' + c.me.code, 6, 60e3)) return json({ ok: true });
  const r = await member(c, room);
  const m = await insertMsg(c, room, 'sys', JSON.stringify({ e: 'shot' }), expFor(c, r.ttl));
  push(c, await roomCodes(c, room), { type: 'msg', m });
  return json({ ok: true });
}

async function markRead(c) {
  const room = c.body.room, id = Number.isInteger(c.body.id) ? c.body.id : -1;
  if (!isRoomId(room) || id < 0) fail(400, 'bad_input');
  await c.env.DB.prepare('UPDATE members SET read_id = MAX(read_id, ?1) WHERE room = ?2 AND code = ?3').bind(id, room, c.me.code).run();
  return json({ ok: true });
}

async function block(c) {
  const code = c.body.code, me = c.me.code, DB = c.env.DB;
  if (!isCode(code) || code === me) fail(400, 'bad_input');
  if (c.body.on) await DB.prepare('INSERT OR IGNORE INTO blocks (code, blocked) VALUES (?, ?)').bind(me, code).run();
  else await DB.prepare('DELETE FROM blocks WHERE code = ? AND blocked = ?').bind(me, code).run();
  const { results } = await DB.prepare('SELECT blocked FROM blocks WHERE code = ?').bind(me).all();
  return json({ blocked: results.map(r => r.blocked) });
}

async function messages(c) {
  const room = c.url.searchParams.get('room') || '';
  const before = parseInt(c.url.searchParams.get('before') || '0', 10) || 9e15;
  if (!isRoomId(room)) fail(400, 'bad_input');
  const r = await member(c, room);
  const { results } = await c.env.DB.prepare(`SELECT ${MSG_COLS} FROM messages m
    WHERE m.room = ?2 AND m.id > ?3 AND m.id < ?4 AND (m.exp IS NULL OR m.exp > ?5)
    ORDER BY m.id DESC LIMIT ${PAGE}`).bind(c.me.code, room, r.cleared, before, c.now).all();
  return json({ msgs: results.reverse(), more: results.length === PAGE });
}

// Everything that changed after "since" in my rooms (new, deleted, opened). Used on reconnect
// and as a polling fallback when the WebSocket isn't available.
async function sync(c) {
  const since = Math.max(0, parseInt(c.url.searchParams.get('since') || '0', 10) || 0);
  const DB = c.env.DB, LIMIT = 200;
  const [rv, rs] = await DB.batch([
    DB.prepare("SELECT v FROM counters WHERE k = 'rev'"),
    DB.prepare(`SELECT ${MSG_COLS} FROM messages m JOIN members mb ON mb.room = m.room AND mb.code = ?1
      WHERE m.rev > ?2 AND m.id > mb.cleared AND (m.exp IS NULL OR m.exp > ?3) ORDER BY m.rev LIMIT ${LIMIT}`).bind(c.me.code, since, c.now),
  ]);
  const msgs = rs.results, more = msgs.length === LIMIT;
  return json({ msgs, rev: more ? msgs[msgs.length - 1].rev : rv.results[0].v, more });
}

async function websocket(c) {
  if ((c.req.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') fail(426, 'expected_websocket');
  if (!c.env.HUB) fail(501, 'no_realtime');
  const headers = new Headers(c.req.headers);
  headers.set('X-Tags', JSON.stringify(['u:' + c.me.code, 's:' + c.th.slice(0, 16)]));
  return hub(c.env).fetch('https://hub/connect', { headers });
}

/* ───────────────────────── tiempo real / realtime ───────────────────────── */

// Un solo Durable Object mantiene los WebSockets (con hibernación: no cobra mientras esperan).
export class Hub {
  constructor(state) {
    this.state = state;
    try { state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong')); } catch { /* old runtime */ }
  }

  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/connect') {
      if ((req.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') return new Response('expected websocket', { status: 426 });
      let tags = [];
      try { tags = JSON.parse(req.headers.get('X-Tags') || '[]'); } catch { /* ignore */ }
      const pair = new WebSocketPair();
      this.state.acceptWebSocket(pair[1], tags.slice(0, 4));
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    if (url.pathname === '/push' && req.method === 'POST') {
      const { to = [], data = null, close = false } = await req.json();
      const msg = data ? JSON.stringify(data) : null;
      let n = 0;
      for (const tag of to) {
        for (const ws of this.state.getWebSockets(tag)) {
          try {
            if (msg) ws.send(msg);
            if (close) ws.close(4001, 'session closed');
            n++;
          } catch { /* already closed */ }
        }
      }
      return new Response(String(n));
    }
    return new Response('not found', { status: 404 });
  }

  webSocketMessage(ws, msg) {
    if (msg === 'ping') { try { ws.send('pong'); } catch { /* ignore */ } }
  }

  webSocketClose(ws, code, reason) {
    try { ws.close(code === 1005 || code === 1006 ? 1000 : code, reason); } catch { /* ignore */ }
  }

  webSocketError(ws) {
    try { ws.close(1011, 'error'); } catch { /* ignore */ }
  }
}

function hub(env) {
  return env.HUB.get(env.HUB.idFromName('hub'));
}

function push(c, codes, data) {
  if (!c.env.HUB || !codes || !codes.length) return;
  const to = [...new Set(codes)].map(x => 'u:' + x);
  c.ctx.waitUntil(hub(c.env).fetch('https://hub/push', { method: 'POST', body: JSON.stringify({ to, data: [].concat(data) }) })
    .catch(e => console.error('push', e)));
}

function kick(c, tags) {
  if (!c.env.HUB || !tags.length) return;
  c.ctx.waitUntil(hub(c.env).fetch('https://hub/push', { method: 'POST', body: JSON.stringify({ to: tags, close: true }) })
    .catch(e => console.error('kick', e)));
}

/* ───────────────────────── helpers de datos ───────────────────────── */

async function insertMsg(c, room, kind, body, exp) {
  const DB = c.env.DB;
  const [, ins] = await DB.batch([
    DB.prepare("UPDATE counters SET v = v + 1 WHERE k = 'rev'"),
    DB.prepare(`INSERT INTO messages (rev, room, sender, kind, body, at, exp)
      VALUES ((SELECT v FROM counters WHERE k = 'rev'), ?1, ?2, ?3, ?4, ?5, ?6) RETURNING id, rev`).bind(room, c.me.code, kind, body, c.now, exp),
  ]);
  const { id, rev } = ins.results[0];
  return { id, rev, room, sender: c.me.code, kind, body, at: c.now, exp, seen: 0, opened: 0 };
}

const expFor = (c, ttl) => (ttl ? c.now + ttl * 1000 : null);

async function member(c, room) {
  const r = await c.env.DB.prepare(`SELECT r.kind, r.ttl, r.stealth, mb.cleared FROM members mb JOIN rooms r ON r.id = mb.room
    WHERE mb.room = ? AND mb.code = ?`).bind(room, c.me.code).first();
  if (!r) fail(403, 'not_member');
  return r;
}

async function roomCodes(c, room) {
  return (await c.env.DB.prepare('SELECT code FROM members WHERE room = ?').bind(room).all()).results.map(r => r.code);
}

async function coMembers(c, code) {
  const { results } = await c.env.DB.prepare('SELECT DISTINCT m2.code FROM members m1 JOIN members m2 ON m2.room = m1.room WHERE m1.code = ?').bind(code).all();
  return results.map(r => r.code);
}

async function deleteRoom(DB, room) {
  await DB.batch([
    DB.prepare('DELETE FROM opens WHERE msg IN (SELECT id FROM messages WHERE room = ?1)').bind(room),
    DB.prepare('DELETE FROM messages WHERE room = ?1').bind(room),
    DB.prepare('DELETE FROM members WHERE room = ?1').bind(room),
    DB.prepare('DELETE FROM rooms WHERE id = ?1').bind(room),
  ]);
}

async function dropEmptyRooms(DB) {
  await DB.batch([
    DB.prepare('DELETE FROM rooms WHERE NOT EXISTS (SELECT 1 FROM members WHERE members.room = rooms.id)'),
    DB.prepare('DELETE FROM messages WHERE room NOT IN (SELECT id FROM rooms)'),
    DB.prepare('DELETE FROM opens WHERE msg NOT IN (SELECT id FROM messages)'),
  ]);
}

async function cleanup(env, now) {
  const DB = env.DB;
  await DB.batch([
    DB.prepare('DELETE FROM opens WHERE msg IN (SELECT id FROM messages WHERE exp IS NOT NULL AND exp <= ?1)').bind(now),
    DB.prepare('DELETE FROM messages WHERE exp IS NOT NULL AND exp <= ?1').bind(now),
    DB.prepare('DELETE FROM sessions WHERE last_seen < ?1').bind(now - SESSION_IDLE),
    DB.prepare('DELETE FROM attempts WHERE reset_at < ?1').bind(now),
  ]);
  await dropEmptyRooms(DB);
}

// Persistent rate limit (D1). Returns seconds to wait, or 0.
async function limited(c, key, max) {
  const r = await c.env.DB.prepare('SELECT n, reset_at FROM attempts WHERE key = ?').bind(key).first();
  return r && r.reset_at > c.now && r.n >= max ? Math.ceil((r.reset_at - c.now) / 1000) : 0;
}

async function hit(c, key, win) {
  const { results } = await c.env.DB.prepare(`INSERT INTO attempts (key, n, reset_at) VALUES (?1, 1, ?2)
    ON CONFLICT(key) DO UPDATE SET
      n = CASE WHEN attempts.reset_at <= ?3 THEN 1 ELSE attempts.n + 1 END,
      reset_at = CASE WHEN attempts.reset_at <= ?3 THEN ?2 ELSE attempts.reset_at END
    RETURNING n`).bind(key, c.now + win, c.now).all();
  return results[0].n;
}

// Light anti-spam limit kept in the Worker's memory (per instance).
const MEM = new Map();
function memLimit(key, max, win) {
  const now = Date.now();
  let e = MEM.get(key);
  if (!e || e.reset < now) { e = { n: 0, reset: now + win }; MEM.set(key, e); }
  if (MEM.size > 5000) for (const [k, v] of MEM) if (v.reset < now) MEM.delete(k);
  return ++e.n <= max;
}

async function newSession(c, code) {
  const token = b64url(rand(32));
  await c.env.DB.prepare('INSERT INTO sessions (token, code, at, last_seen) VALUES (?, ?, ?, ?)').bind(await sha256hex(token), code, c.now, c.now).run();
  return token;
}

async function authenticate(c, allowQuery) {
  const h = c.req.headers.get('Authorization') || '';
  let token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!token && allowQuery) token = c.url.searchParams.get('t') || '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const th = await sha256hex(token);
  const s = await c.env.DB.prepare(`SELECT s.code, s.last_seen, u.name, u.pub FROM sessions s
    JOIN users u ON u.code = s.code AND u.deleted = 0 WHERE s.token = ?`).bind(th).first();
  if (!s || s.last_seen < c.now - SESSION_IDLE) return null;
  if (s.last_seen < c.now - 5 * 60e3) {
    c.ctx.waitUntil(c.env.DB.prepare('UPDATE sessions SET last_seen = ? WHERE token = ?').bind(c.now, th).run().catch(() => {}));
  }
  c.th = th;
  return { code: s.code, name: s.name, pub: s.pub };
}

/* ───────────────────────── validación / utilidades ───────────────────────── */

class HttpError extends Error {
  constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra || {}; }
}
function fail(status, code, extra) { throw new HttpError(status, code, extra); }

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...CORS },
  });
}

async function readJson(req, max) {
  const text = await req.text();
  if (text.length > max) fail(413, 'too_large');
  let v;
  try { v = text ? JSON.parse(text) : {}; } catch { fail(400, 'bad_json'); }
  if (!v || typeof v !== 'object' || Array.isArray(v)) fail(400, 'bad_json');
  return v;
}

const isCode = s => typeof s === 'string' && /^[1-9]\d{4}$/.test(s);
const isGroupId = s => typeof s === 'string' && /^g:[0-9a-f]{32}$/.test(s);
const isRoomId = s => typeof s === 'string' && /^(d:[1-9]\d{4}:[1-9]\d{4}|g:[0-9a-f]{32})$/.test(s);
const isB64 = (s, min, max) => typeof s === 'string' && s.length >= min && s.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
const isSealed = (s, max) => typeof s === 'string' && s.length <= max && /^[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/]{24,}={0,2}$/.test(s);
const dmId = (a, b) => 'd:' + [a, b].sort().join(':');
const cleanName = n => String(n || '').replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, '').trim().slice(0, 32);

const te = new TextEncoder(), td = new TextDecoder();
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const randInt = n => crypto.getRandomValues(new Uint32Array(1))[0] % n;
const hex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');

function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const b64url = u8 => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sha256hex(s) {
  return hex(await crypto.subtle.digest('SHA-256', te.encode(s)));
}

// Server keys come from the PEPPER secret (wrangler secret put PEPPER). Never stored in D1.
let KEYS = null;
async function srvKeys(env) {
  if (KEYS && KEYS.p === env.PEPPER) return KEYS;
  const base = await crypto.subtle.importKey('raw', te.encode(env.PEPPER), 'HKDF', false, ['deriveKey']);
  const info = s => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode(s) });
  const mac = await crypto.subtle.deriveKey(info('cifra/srv/mac'), base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
  const box = await crypto.subtle.deriveKey(info('cifra/srv/box'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  KEYS = { p: env.PEPPER, mac, box };
  return KEYS;
}

async function makeVerifier(env, code, auth) {
  const k = await srvKeys(env);
  return hex(await crypto.subtle.sign('HMAC', k.mac, te.encode(code + ':' + auth)));
}

// Extra layer: wrapped keys are stored sealed with the server key, so a copy of the
// database alone can't be used to guess passwords offline.
async function sealSrv(env, text, aad) {
  const k = await srvKeys(env);
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, k.box, te.encode(text));
  return b64(iv) + '.' + b64(new Uint8Array(ct));
}

async function openSrv(env, sealed, aad) {
  const k = await srvKeys(env);
  const i = sealed.indexOf('.');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(sealed.slice(0, i)), additionalData: te.encode(aad) }, k.box, unb64(sealed.slice(i + 1)));
  return td.decode(pt);
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
}
