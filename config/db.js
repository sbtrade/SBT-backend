const { Pool } = require('pg');
require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

// Neon requires SSL. We dynamically enable it based on production environment or if the URL contains "neon.tech"
const sslConfig = process.env.DATABASE_URL && process.env.DATABASE_URL.includes('neon.tech')
  ? { rejectUnauthorized: false }
  : false;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: sslConfig,
});

pool.on('connect', () => {
  console.log('Database connected successfully.');
});

pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};
