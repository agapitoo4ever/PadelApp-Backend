require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db'); // conexión MariaDB

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

// --- GET de prueba para navegador ---
app.get('/', (req, res) => {
  res.send(`
    <h1>Backend de Padel funcionando ✅</h1>
    <p>Usa POST /login y POST /register desde POSTMAN o Flutter</p>
  `);
});

// --- Registro de usuario ---
app.post('/register', async (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  try {
    const hash = await bcrypt.hash(contrasena, 10);
    const [result] = await db.query(
      'INSERT INTO usuarios (nombre, correo, contrasena) VALUES (?, ?, ?)',
      [nombre, correo, hash]
    );
    res.json({ success: true, usuario: { id: result.insertId, nombre, correo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en la base de datos o correo ya registrado' });
  }
});

// --- Login ---
app.post('/login', async (req, res) => {
  const { correo, contrasena } = req.body;

  if (!correo || !contrasena) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  try {
    const [rows] = await db.query('SELECT * FROM usuarios WHERE correo = ?', [correo]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuario no existe' });

    const user = rows[0];
    const valid = await bcrypt.compare(contrasena, user.contrasena);

    if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.id, correo: user.correo }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ success: true, token, usuario: { id: user.id, nombre: user.nombre, correo: user.correo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// --- Inicio del servidor ---
app.listen(PORT, '0.0.0.0', () => console.log(`Servidor escuchando en puerto ${PORT}`));
