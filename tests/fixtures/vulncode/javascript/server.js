// API de clientes. Código con fallos plantados para pruebas.
const express = require('express');
const { exec } = require('child_process');
const app = express();

// hardcoded-secret
const JWT_SECRET = 'secret';
const STRIPE_KEY = 'sk_live_51H8xYzKqLyjWDarjtT1zdp7dcAbCdEfGh';

app.get('/buscar', (req, res) => {
  // sql-injection
  const q = req.query.q;
  db.query("SELECT * FROM clientes WHERE nombre = '" + q + "'", (e, r) => res.json(r));
});

app.get('/ping', (req, res) => {
  // command-injection
  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));
});

app.get('/render', (req, res) => {
  // xss: se devuelve entrada sin escapar
  res.send('<h1>Hola ' + req.query.nombre + '</h1>');
});

app.get('/eval', (req, res) => {
  // code-injection
  res.send(String(eval(req.query.expr)));
});

module.exports = app;
