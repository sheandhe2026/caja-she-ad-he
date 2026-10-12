const crypto = require('crypto');
const { sql, init, hash, auth } = require('../lib/db');

const str = (s) => String(s || '').trim();

module.exports = async (req, res) => {
  try {
    await init();
    const me = await auth(req);
    if (!me) return res.status(401).json({ error: 'auth' });
    if (me.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador' });
    const b = req.body || {};
    const admins = async () => (await sql`SELECT count(*)::int AS n FROM usr WHERE role = 'admin'`)[0].n;

    if (b.action === 'add') {
      const name = str(b.name), user = str(b.user).toLowerCase(), pass = String(b.pass || '');
      const role = b.role === 'admin' ? 'admin' : 'seller';
      if (!name || !user || pass.length < 4) return res.status(400).json({ error: 'Datos incompletos' });
      try {
        await sql`INSERT INTO usr (id, name, username, role, pass) VALUES (${crypto.randomBytes(4).toString('hex')}, ${name}, ${user}, ${role}, ${hash(pass)})`;
      } catch (e) { return res.status(409).json({ error: 'Ese usuario ya existe' }); }
    } else if (b.action === 'edit') {
      const [u] = await sql`SELECT * FROM usr WHERE id = ${b.id}`;
      if (!u) return res.status(404).json({ error: 'No existe' });
      const name = str(b.name), user = str(b.user).toLowerCase(), role = b.role === 'admin' ? 'admin' : 'seller';
      if (!name || !user) return res.status(400).json({ error: 'Nombre y usuario son obligatorios' });
      if (b.pass && String(b.pass).length < 4) return res.status(400).json({ error: 'La contraseña debe tener mínimo 4 caracteres' });
      if (u.role === 'admin' && role !== 'admin' && (await admins()) < 2) return res.status(400).json({ error: 'Debe quedar al menos un administrador' });
      try {
        await sql`UPDATE usr SET name = ${name}, username = ${user}, role = ${role} WHERE id = ${b.id}`;
      } catch (e) { return res.status(409).json({ error: 'Ese usuario ya existe' }); }
      if (b.pass) await sql`UPDATE usr SET pass = ${hash(String(b.pass))} WHERE id = ${b.id}`;
    } else if (b.action === 'del') {
      if (b.id === me.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
      const [u] = await sql`SELECT role FROM usr WHERE id = ${b.id}`;
      if (u && u.role === 'admin' && (await admins()) < 2) return res.status(400).json({ error: 'Debe quedar al menos un administrador' });
      await sql`DELETE FROM usr WHERE id = ${b.id}`;
    } else return res.status(400).json({ error: 'accion' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server' });
  }
};
