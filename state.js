const { sql, init, auth } = require('../lib/db');

module.exports = async (req, res) => {
  try {
    await init();
    const me = await auth(req);
    if (!me) return res.status(401).json({ error: 'auth' });
    const admin = me.role === 'admin';
    const [s] = await sql`SELECT (SELECT count(*)::text FROM rec) || '|' || (SELECT COALESCE(max(updated_at)::text, '') FROM rec) || '|' || (SELECT md5(COALESCE(string_agg(id || name || username || role, ',' ORDER BY id), '')) FROM usr) AS sig`;
    const sig = s.sig + '|' + me.id + me.role + me.name;
    if (req.body && req.body.sig === sig) return res.json({ same: true });
    const all = await sql`SELECT k, v FROM rec ORDER BY seq`;
    const rows = admin ? all : all.filter((r) => !/^(buy|hist|log):/.test(r.k));
    const users = admin ? await sql`SELECT id, name, username AS "user", role FROM usr ORDER BY (id = 'u1') DESC, name` : [];
    res.json({ me, rows, users, sig });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server' });
  }
};
