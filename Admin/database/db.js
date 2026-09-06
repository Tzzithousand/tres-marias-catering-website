/**
 * TRES MARIAS - DATABASE CONNECTION POOL
 * File: database/db.js
 * Description: Connects to MySQL Server 8.0 on localhost (localhost:3306)
 */

const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'tres_marias_user_db',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test connection on startup
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('Successfully connected to tres_marias_user_db');
    connection.release();
  } catch (error) {
    console.error('Error in connecting to MySQL:', error.message);
  }
}

testConnection();

module.exports = pool;
