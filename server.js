const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db'); // db.js configurado para PostgreSQL

require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json()); // Necesario para recibir JSON

// Ruta de prueba
app.get('/', (req, res) => {
  res.send('Backend de Padel funcionando ✅');
});

// -------------------- REGISTRO --------------------
app.post('/register', async (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  try {
    // Verificar si el correo ya existe
    const userExist = await pool.query(
      'SELECT * FROM usuarios WHERE correo = $1',
      [correo]
    );

    if (userExist.rows.length > 0) {
      return res.status(400).json({ error: 'Correo ya registrado' });
    }

    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(contrasena, 10);

    // Insertar usuario
    await pool.query(
      'INSERT INTO usuarios (nombre, correo, contrasena) VALUES ($1, $2, $3)',
      [nombre, correo, hashedPassword]
    );

    return res.status(201).json({ mensaje: 'Usuario registrado correctamente' });

  } catch (err) {
    console.error('Error en registro:', err);
    return res.status(500).json({ error: 'Error en la base de datos' });
  }
});

// -------------------- LOGIN --------------------
app.post('/login', async (req, res) => {
  const { correo, contrasena } = req.body;

  if (!correo || !contrasena) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  try {
    const user = await pool.query(
      'SELECT * FROM usuarios WHERE correo = $1',
      [correo]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }

    const validPass = await bcrypt.compare(contrasena, user.rows[0].contrasena);
    if (!validPass) {
      return res.status(400).json({ error: 'Contraseña incorrecta' });
    }

    // Crear token JWT
    const token = jwt.sign(
      { id: user.rows[0].id, nombre: user.rows[0].nombre },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Devolver nombre y token
    return res.json({
      mensaje: 'Login correcto',
      token,
      usuario: {
        id: user.rows[0].id,
        nombre: user.rows[0].nombre,
        correo: user.rows[0].correo,
      },
    });

  } catch (err) {
    console.error('Error en login:', err);
    return res.status(500).json({ error: 'Error en la base de datos' });
  }
});

// -------------------- SERVIDOR --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
