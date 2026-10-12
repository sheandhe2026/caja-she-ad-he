const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
const sql = neon(url || 'postgres://missing');
const secret = process.env.SESSION_SECRET || crypto.createHash('sha256').update('she-he|' + url).digest('hex');

const hash = (p) => {
  const s = crypto.randomBytes(16).toString('hex');
  return s + ':' + crypto.scryptSync(p, s, 64).toString('hex');
};
const check = (p, st) => {
  const [s, h] = String(st).split(':');
  const a = Buffer.from(h || '', 'hex'), b = crypto.scryptSync(p, s || '', 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const sign = (u) => {
  const p = Buffer.from(JSON.stringify({ id: u.id, exp: Date.now() + 30 * 864e5 })).toString('base64url');
  return p + '.' + crypto.createHmac('sha256', secret).update(p).digest('base64url');
};

async function auth(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [p, s] = t.split('.');
  if (!p || !s) return null;
  const ok = crypto.createHmac('sha256', secret).update(p).digest('base64url');
  if (s.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(ok))) return null;
  let d;
  try { d = JSON.parse(Buffer.from(p, 'base64url').toString()); } catch (e) { return null; }
  if (!d.exp || d.exp < Date.now()) return null;
  const r = await sql`SELECT id, name, username, role FROM usr WHERE id = ${d.id}`;
  return r[0] ? { id: r[0].id, name: r[0].name, user: r[0].username, role: r[0].role } : null;
}

let ready = null;
function init() {
  if (!ready) {
    ready = (async () => {
      await sql`CREATE TABLE IF NOT EXISTS rec (k text PRIMARY KEY, v jsonb NOT NULL, seq bigserial, updated_at timestamptz DEFAULT now())`;
      await sql`CREATE TABLE IF NOT EXISTS usr (id text PRIMARY KEY, name text NOT NULL, username text UNIQUE NOT NULL, role text NOT NULL, pass text NOT NULL)`;
      const [{ n }] = await sql`SELECT count(*)::int AS n FROM usr`;
      if (!n) await sql`INSERT INTO usr (id, name, username, role, pass) VALUES ('u1', 'Administrador', 'admin', 'admin', ${hash('admin123')}) ON CONFLICT DO NOTHING`;
      const [{ m }] = await sql`SELECT count(*)::int AS m FROM rec`;
      if (!m) {
        const P = [['Corona', 'Cervezas', 175], ['Coronita', 'Cervezas', 125], ['Presidente Mediana', 'Cervezas', 200], ['Presidente Pequeña', 'Cervezas', 150], ['ONE', 'Cervezas', 150],
          ['Agua Planeta', 'Bebidas', 25], ['Agua Tónica', 'Bebidas', 50], ['Coca-Cola', 'Bebidas', 35], ['Gatorade', 'Bebidas', 100], ['Sprite', 'Bebidas', 35]];
        const put = (k, v) => sql`INSERT INTO rec (k, v) VALUES (${k}, ${JSON.stringify(v)}::jsonb) ON CONFLICT (k) DO NOTHING`;
        const q = [put('meta:cats', { list: ['Cervezas', 'Bebidas'] }), put('cash:meta', { open: false })];
        P.forEach((p, i) => q.push(put('prod:p' + (i + 1), { id: 'p' + (i + 1), name: p[0], cat: p[1], price: p[2], stock: 0, min: 6 })));
        await sql.transaction(q);
      }
    })().catch((e) => { ready = null; throw e; });
  }
  return ready;
}

module.exports = { sql, init, hash, check, sign, auth };
