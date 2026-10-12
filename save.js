const { sql, init, auth } = require('../lib/db');

const KEY = /^(meta|prod|cred|buy|hist|log|cash|sale|tab|exp|col)(:[A-Za-z0-9_-]+)?$/;
const SELLER_PUT = /^(tab|sale|exp|col|cred|log|hist):|^cash:meta$/;
const SELLER_DEL = /^(tab|sale|exp|col):/;

module.exports = async (req, res) => {
  try {
    await init();
    const me = await auth(req);
    if (!me) return res.status(401).json({ error: 'auth' });
    const admin = me.role === 'admin';
    const { ops, replace } = req.body || {};
    if (!Array.isArray(ops)) return res.status(400).json({ error: 'ops' });
    if (replace && !admin) return res.status(403).json({ error: 'Solo el administrador puede restaurar' });

    const q = [];
    if (replace) q.push(sql`DELETE FROM rec`);
    for (const o of ops) {
      const k = String((o && o.k) || '');
      if (!KEY.test(k)) continue;
      if ('put' in o) {
        if (!admin && !SELLER_PUT.test(k)) return res.status(403).json({ error: 'Sin permiso: ' + k });
        q.push(sql`INSERT INTO rec (k, v) VALUES (${k}, ${JSON.stringify(o.put)}::jsonb) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = now()`);
      } else if ('patch' in o) {
        if (!admin) return res.status(403).json({ error: 'Sin permiso: ' + k });
        q.push(sql`UPDATE rec SET v = v || ${JSON.stringify(o.patch)}::jsonb, updated_at = now() WHERE k = ${k}`);
      } else if ('inc' in o) {
        if (!/^prod:/.test(k)) continue;
        q.push(sql`UPDATE rec SET v = jsonb_set(v, '{stock}', to_jsonb(GREATEST(0, COALESCE((v->>'stock')::numeric, 0) + ${Number(o.inc) || 0}::numeric))), updated_at = now() WHERE k = ${k}`);
      } else if (o.del) {
        if (!admin && !SELLER_DEL.test(k)) return res.status(403).json({ error: 'Sin permiso: ' + k });
        q.push(sql`DELETE FROM rec WHERE k = ${k}`);
      }
    }
    if (q.length) await sql.transaction(q);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server' });
  }
};
