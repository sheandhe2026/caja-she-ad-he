const { sql, init, check, sign } = require('../lib/db');

module.exports = async (req, res) => {
  try {
    await init();
    const { user, pass } = req.body || {};
    const r = await sql`SELECT * FROM usr WHERE username = ${String(user || '').trim().toLowerCase()}`;
    const u = r[0];
    if (!u || !check(String(pass || ''), u.pass)) {
      await new Promise((x) => setTimeout(x, 600));
      return res.status(401).json({ error: 'bad' });
    }
    res.json({
      token: sign(u),
      user: { id: u.id, name: u.name, user: u.username, role: u.role },
      warn: u.username === 'admin' && check('admin123', u.pass),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server' });
  }
};
