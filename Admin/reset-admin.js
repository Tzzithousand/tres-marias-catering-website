/**
 * TRES MARIAS - QUICK ADMIN ACCOUNT RESET
 * Run this anytime you get locked out during manual testing:
 * Command: node reset-admin.js
 */
const db = require('./database/db');

async function reset() {
  try {
    await db.query(`
      UPDATE users 
      SET failed_login_attempts = 0, 
          lockout_until = NULL, 
          failed_otp_attempts = 0, 
          otp_lockout_until = NULL,
          otp_code = '1234',
          otp_expires_at = DATE_ADD(NOW(), INTERVAL 5 MINUTE),
          status = 'active'
      WHERE email = 'admin@email.com'
    `);
    console.log('\x1b[32m%s\x1b[0m', '✓ [SUCCESS] Admin account has been reset and unlocked!');
    console.log('Credentials: admin@email.com | Password123 | Default OTP: 1234');
  } catch (err) {
    console.error('Failed to reset admin account:', err.message);
  } finally {
    await db.end();
  }
}

reset();
